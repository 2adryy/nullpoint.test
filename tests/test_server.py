"""Integration tests: a real server on a random port and real clients over TCP."""

import copy
import json
import os
import time
import unittest

from tests.helpers import PASSWORD, ServerTestCase
from securechat import crypto_utils as cu
from securechat.client_core import ChatError, ServerKeyChanged


class AuthTests(ServerTestCase):
    def test_register_and_login(self):
        a = self.user("Ahmed")
        self.assertEqual(a.username, "Ahmed")
        self.assertRegex(a.my_fingerprint, r"^([0-9A-F]{4} ){7}[0-9A-F]{4}$")
        self.assertIsNotNone(a.profile["created"])
        self.assertIsNone(a.profile["last_login"])   # first login

    def test_private_key_never_sent_and_stored_encrypted(self):
        self.user("Ahmed")
        with open(f"{self.tmp}/ahmed/keys/ahmed_private.pem", "rb") as f:
            self.assertIn(b"ENCRYPTED", f.read())
        row = self.server.db.get_user("Ahmed")
        self.assertIn("PUBLIC KEY", row["public_key"])
        self.assertNotIn("PRIVATE", row["public_key"])

    def test_wrong_password_and_unknown_user_give_same_error(self):
        self.user("Ahmed").logout()
        c = self.connected("ahmed")
        with self.assertRaises(ChatError) as wrong:
            c.login("Ahmed", "Wr0ng!pass")
        c2 = self.connected("ahmed")
        os.makedirs(f"{self.tmp}/ahmed/keys", exist_ok=True)
        open(f"{self.tmp}/ahmed/keys/ghost_private.pem", "w").close()
        with self.assertRaises(ChatError) as unknown:
            c2.login("Ghost", "Wr0ng!pass")
        self.assertEqual(str(wrong.exception), str(unknown.exception))

    def test_lockout_after_five_failures_and_admin_unlock(self):
        self.user("Ahmed").logout()
        c = self.connected("ahmed")
        for _ in range(5):
            with self.assertRaises(ChatError):
                c.login("Ahmed", "Wr0ng!pass")
        with self.assertRaisesRegex(ChatError, "locked"):
            c.login("Ahmed", PASSWORD)          # even the right password is refused now
        ok, _ = self.server.admin_unlock("root", "Ahmed")
        self.assertTrue(ok)
        c.login("Ahmed", PASSWORD)
        kinds = [e["kind"] for e in self.server.db.recent_events(username="Ahmed")]
        self.assertIn("account_locked", kinds)

    def test_duplicate_session_refused(self):
        self.user("Ahmed")
        c = self.connected("ahmed")
        with self.assertRaisesRegex(ChatError, "already logged in"):
            c.login("Ahmed", PASSWORD)

    def test_registration_can_be_closed(self):
        self.server.admin_settings("root", {"registration_open": False})
        c = self.connected()
        with self.assertRaisesRegex(ChatError, "closed"):
            c.register("Ahmed", PASSWORD)

    def test_server_enforces_policy_even_if_client_skips_it(self):
        c = self.connected()
        reply = c._request({"type": "register", "username": "x", "password": "weak",
                            "public_key": cu.public_pem(cu.generate_private_key())})
        self.assertFalse(reply["ok"])

    def test_no_local_key(self):
        c = self.connected()
        with self.assertRaisesRegex(ChatError, "No private key"):
            c.login("Nobody", PASSWORD)

    def test_server_key_change_detected(self):
        c = self.connected()
        c.logout()
        known = json.load(open(f"{self.tmp}/client/known_servers.json"))
        address = next(iter(known))
        known[address] = "0000 0000 0000 0000 0000 0000 0000 0000"   # pretend we saw another key before
        json.dump(known, open(f"{self.tmp}/client/known_servers.json", "w"))
        with self.assertRaises(ServerKeyChanged):
            self.new_client().connect("127.0.0.1", self.server.port)

    def test_change_password(self):
        a = self.user("Ahmed")
        with self.assertRaisesRegex(ChatError, "wrong"):
            a.change_password("Wr0ng!pass", "N3w!password")
        a.change_password(PASSWORD, "N3w!password")
        a.logout()
        key = open(f"{self.tmp}/ahmed/keys/ahmed_private.pem", "rb").read()
        with self.assertRaises(cu.CryptoError):
            cu.load_private_key(key, PASSWORD)              # old password no longer unlocks it
        cu.load_private_key(key, "N3w!password")
        c = self.connected("ahmed")
        with self.assertRaises(ChatError):
            c.login("Ahmed", PASSWORD)
        c.login("Ahmed", "N3w!password")

    def test_my_security_events(self):
        a = self.user("Ahmed")
        kinds = [e["kind"] for e in a.my_security_events()]
        self.assertIn("login", kinds)
        self.assertIn("registered", kinds)


class FriendTests(ServerTestCase):
    def test_strangers_cannot_message(self):
        a = self.user("Ahmed")
        self.user("Omar")
        with self.assertRaisesRegex(ChatError, "not in your friends"):
            a.send_text("Omar", "hi")
        # a modified client sending the packet anyway is stopped by the server
        header = {"from": "Ahmed", "to": "Omar", "ts": time.time(), "id": "x", "kind": "text"}
        omar_pub = cu.load_public_key(self.server.db.get_user("Omar")["public_key"])
        packet = cu.encrypt_message(a._private_key, omar_pub, header, b"hi")
        a.channel.send({"type": "relay", "to": "Omar", "packet": packet})
        self.assertIn("only message friends", a.wait_for("error"))

    def test_request_accept_and_chat(self):
        a, b = self.pair()
        a.send_text("Omar", "Hi Omar")
        self.assertEqual(b.wait_for("message")["text"], "Hi Omar")

    def test_bad_requests(self):
        a = self.user("Ahmed")
        self.user("Omar")
        with self.assertRaisesRegex(ChatError, "No user"):
            a.add_friend("Ghost")
        with self.assertRaisesRegex(ChatError, "yourself"):
            a.add_friend("Ahmed")
        a.add_friend("Omar")
        with self.assertRaisesRegex(ChatError, "already sent"):
            a.add_friend("omar")

    def test_mutual_requests_become_friends(self):
        a = self.user("Ahmed")
        b = self.user("Omar")
        a.add_friend("Omar")
        b.wait_for("friends", match=lambda d: "Ahmed" in d["incoming"])
        self.assertIn("now friends", b.add_friend("Ahmed"))
        a.wait_for("friends", match=self.friend_online("Omar"))

    def test_decline(self):
        a = self.user("Ahmed")
        b = self.user("Omar")
        a.add_friend("Omar")
        b.wait_for("friends", match=lambda d: "Ahmed" in d["incoming"])
        b.respond_friend("Ahmed", False)
        d = a.wait_for("friends", match=lambda d: not d["outgoing"])
        self.assertEqual(d["contacts"], [])
        self.assertFalse(self.server.db.are_friends("Ahmed", "Omar"))

    def test_remove_friend_stops_messages(self):
        a, b = self.pair()
        a.remove_friend("Omar")
        a.wait_for("friends", match=lambda d: d["contacts"] == [])
        with self.assertRaises(ChatError):
            a.send_text("Omar", "still there?")

    def test_offline_friend(self):
        a, b = self.pair()
        b.logout()
        a.wait_for("friends", match=lambda d: d["contacts"] and not d["contacts"][0]["online"])
        with self.assertRaisesRegex(ChatError, "offline"):
            a.send_text("Omar", "hello?")


class MessageSecurityTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.a, self.b = self.pair()
        self.omar_pub = cu.load_public_key(self.a.contacts["Omar"]["public_key"])

    def raw_packet(self, text=b"hello", **header_overrides):
        header = {"from": "Ahmed", "to": "Omar", "ts": time.time(), "id": os.urandom(8).hex(), "kind": "text"}
        header.update(header_overrides)
        return cu.encrypt_message(self.a._private_key, self.omar_pub, header, text)

    def send_raw(self, packet):
        self.a.channel.send({"type": "relay", "to": "Omar", "packet": packet})

    def test_delivery_and_server_counts_but_cannot_read(self):
        self.a.send_text("Omar", "top secret 123")
        self.assertEqual(self.b.wait_for("message")["text"], "top secret 123")
        self.assertEqual(self.server.stats["relayed"], 1)
        dash = json.dumps(self.server.dashboard())
        self.assertNotIn("top secret 123", dash)   # the admin view has no message content

    def test_tampered_message_rejected(self):
        p = self.raw_packet()
        ct = bytearray(cu.b64d(p["ct"]))
        ct[3] ^= 0xFF
        p["ct"] = cu.b64e(bytes(ct))
        self.send_raw(p)
        self.assertIn("Invalid signature", self.b.wait_for("security")["text"])

    def test_replayed_message_rejected(self):
        p = self.raw_packet()
        self.send_raw(p)
        self.b.wait_for("message")
        self.send_raw(copy.deepcopy(p))
        self.assertIn("replay", self.b.wait_for("security")["text"])

    def test_old_message_rejected(self):
        self.send_raw(self.raw_packet(ts=time.time() - 600))
        self.assertIn("5-minute window", self.b.wait_for("security")["text"])

    def test_spoofed_sender_blocked_by_server(self):
        self.send_raw(self.raw_packet(**{"from": "Omar"}))
        self.assertIn("does not match", self.a.wait_for("error"))
        self.assertEqual(self.server.db.recent_events(1)[0]["kind"], "spoofed_packet")

    def test_changed_contact_key_blocks_until_trusted(self):
        pins_path = f"{self.tmp}/ahmed/known_keys_ahmed.json"
        pins = json.load(open(pins_path))
        pins["Omar"]["fingerprint"] = "FFFF " * 7 + "FFFF"
        json.dump(pins, open(pins_path, "w"))
        self.b.logout()                      # trigger a new friends list from the server
        self.b = self.new_client("omar")
        self.b.connect("127.0.0.1", self.server.port)
        self.b.login("Omar", PASSWORD)
        self.assertIn("KEY CHANGED", self.a.wait_for("security")["text"])
        self.a.wait_for("friends", match=self.friend_online("Omar"))
        with self.assertRaisesRegex(ChatError, "key changed"):
            self.a.send_text("Omar", "hi")
        self.a.trust_new_key("Omar")
        self.a.send_text("Omar", "hi")


class AdminTests(ServerTestCase):
    def test_kick(self):
        a = self.user("Ahmed")
        ok, _ = self.server.admin_kick("root", "Ahmed")
        self.assertTrue(ok)
        self.assertIn("administrator", a.wait_for("disconnected"))
        self.assertEqual(self.server.db.audit_log()[0]["action"], "kick")

    def test_ban_disconnects_and_blocks_login(self):
        a = self.user("Ahmed")
        self.server.admin_ban("root", "Ahmed", True)
        self.assertIn("banned", a.wait_for("disconnected"))
        c = self.connected("ahmed")
        with self.assertRaisesRegex(ChatError, "banned"):
            c.login("Ahmed", PASSWORD)
        self.server.admin_ban("root", "Ahmed", False)
        c2 = self.connected("ahmed")
        c2.login("Ahmed", PASSWORD)

    def test_banned_user_hidden_from_friends(self):
        a, b = self.pair()
        self.server.admin_ban("root", "Omar", True)
        a.wait_for("friends", match=lambda d: d["contacts"] == [])

    def test_delete_user(self):
        a, b = self.pair()
        ok, _ = self.server.admin_delete("root", "Omar")
        self.assertTrue(ok)
        b.wait_for("disconnected")
        a.wait_for("friends", match=lambda d: d["contacts"] == [])
        self.assertIsNone(self.server.db.get_user("Omar"))

    def test_announcement(self):
        a, b = self.pair()
        ok, msg = self.server.admin_announce("root", "Server restarts at 18:00")
        self.assertTrue(ok, msg)
        self.assertEqual(a.wait_for("announcement")["text"], "Server restarts at 18:00")
        self.assertEqual(b.wait_for("announcement")["text"], "Server restarts at 18:00")
        self.assertFalse(self.server.admin_announce("root", "x" * 501)[0])
        self.assertFalse(self.server.admin_announce("root", "   ")[0])

    def test_announcements_shown_on_next_login(self):
        self.server.admin_announce("root", "Welcome!")
        a = self.user("Ahmed")
        self.assertEqual(a.announcements[-1]["text"], "Welcome!")

    def test_settings_validation(self):
        self.assertFalse(self.server.admin_settings("root", {"max_failed_logins": 1})[0])
        self.assertFalse(self.server.admin_settings("root", {"lockout_seconds": "abc"})[0])
        self.assertTrue(self.server.admin_settings("root", {"max_failed_logins": 3})[0])
        self.assertEqual(self.server.settings()["max_failed_logins"], 3)

    def test_dashboard_contents(self):
        self.pair()
        d = self.server.dashboard()
        self.assertEqual(d["stats"]["registered"], 2)
        self.assertEqual(d["stats"]["online"], 2)
        self.assertEqual(d["stats"]["friendships"], 1)
        user = d["users"][0]
        self.assertNotIn("pw_hash", user)
        self.assertNotIn("public_key", user)
        self.assertIn("fingerprint", user)


if __name__ == "__main__":
    unittest.main()
