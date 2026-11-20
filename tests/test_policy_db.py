"""Unit tests for the password/username policy and the SQLite database."""

import os
import shutil
import tempfile
import unittest

from tests import helpers  # noqa: F401  (sets fast bcrypt rounds)
from securechat import database, policy
from securechat.database import UserDB


class PolicyTests(unittest.TestCase):
    def test_valid_usernames(self):
        for name in ("Ahmed", "omar_99", "abc", "A" * 20):
            self.assertIsNone(policy.check_username(name), name)

    def test_invalid_usernames(self):
        for name in ("", "ab", "A" * 21, "has space", "semi;colon", "émile", "../x", "<script>"):
            self.assertIsNotNone(policy.check_username(name), name)

    def test_valid_passwords(self):
        for pw in ("Str0ng!pass", "abcDEF12", "abc!@#123", "ABC!@#def"):
            self.assertIsNone(policy.check_password(pw), pw)

    def test_weak_passwords(self):
        for pw in ("", "Sh0rt!", "alllowercase", "ALLUPPER123", "lowerupperONLY", "12345678!"):
            self.assertIsNotNone(policy.check_password(pw), pw)

    def test_password_over_72_bytes_rejected(self):
        """bcrypt ignores bytes after 72, so longer passwords are refused, not silently cut."""
        self.assertIsNone(policy.check_password("Aa1!" + "x" * 68))        # exactly 72
        self.assertIsNotNone(policy.check_password("Aa1!" + "x" * 69))     # 73
        self.assertIsNotNone(policy.check_password("Aa1!" + "é" * 35))     # 74 bytes in UTF-8


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "users.db")
        self.db = UserDB(self.path)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_password_is_hashed_not_stored(self):
        self.assertTrue(self.db.add_user("Ahmed", "Str0ng!pass", "PUBKEY"))
        row = self.db.get_user("Ahmed")
        self.assertTrue(row["pw_hash"].startswith("$2"))
        self.assertTrue(database.check_password("Str0ng!pass", row["pw_hash"]))
        self.assertFalse(database.check_password("wrong", row["pw_hash"]))
        self.db.close()
        with open(self.path, "rb") as f:
            self.assertNotIn(b"Str0ng!pass", f.read())
        self.db = UserDB(self.path)

    def test_same_password_gives_different_hashes(self):
        """bcrypt uses a random salt per user."""
        self.db.add_user("Ahmed", "Str0ng!pass", "K1")
        self.db.add_user("Omar", "Str0ng!pass", "K2")
        self.assertNotEqual(self.db.get_user("Ahmed")["pw_hash"], self.db.get_user("Omar")["pw_hash"])

    def test_unknown_user_check_is_false(self):
        self.assertFalse(database.check_password("anything", None))

    def test_usernames_are_case_insensitive_and_unique(self):
        self.assertTrue(self.db.add_user("Ahmed", "Str0ng!pass", "K"))
        self.assertFalse(self.db.add_user("ahmed", "Str0ng!pass", "K"))
        self.assertEqual(self.db.get_user("AHMED")["username"], "Ahmed")

    def test_sql_injection_is_harmless(self):
        evil = "x' OR '1'='1"
        self.assertIsNone(self.db.get_user(evil))
        self.db.add_user("Ahmed", "Str0ng!pass", "K")
        self.assertIsNone(self.db.get_user("Ahmed' --"))
        self.assertEqual(self.db.count_users(), 1)

    def test_admins_and_users_share_no_names(self):
        self.assertTrue(self.db.add_admin("root", "Adm1n!pass"))
        self.assertFalse(self.db.add_user("root", "Str0ng!pass", "K"))
        self.db.add_user("Ahmed", "Str0ng!pass", "K")
        self.assertFalse(self.db.add_admin("Ahmed", "Adm1n!pass"))

    def test_friend_lifecycle(self):
        for n in ("Ahmed", "Omar"):
            self.db.add_user(n, "Str0ng!pass", "K")
        self.db.add_friend_request("Ahmed", "Omar")
        self.assertEqual(self.db.friend_lists("Ahmed")["outgoing"], ["Omar"])
        self.assertEqual(self.db.friend_lists("Omar")["incoming"], ["Ahmed"])
        self.assertFalse(self.db.are_friends("Ahmed", "Omar"))
        self.assertFalse(self.db.accept_friend("Omar", "Ahmed"))   # only the addressee can accept
        self.assertTrue(self.db.accept_friend("Ahmed", "Omar"))
        self.assertTrue(self.db.are_friends("Omar", "Ahmed"))
        self.assertEqual(self.db.friend_lists("Omar")["friends"], ["Ahmed"])
        self.assertTrue(self.db.remove_friend("Omar", "Ahmed"))
        self.assertFalse(self.db.are_friends("Ahmed", "Omar"))

    def test_delete_user_removes_friendships(self):
        for n in ("Ahmed", "Omar"):
            self.db.add_user(n, "Str0ng!pass", "K")
        self.db.add_friend_request("Ahmed", "Omar")
        self.db.accept_friend("Ahmed", "Omar")
        self.assertTrue(self.db.delete_user("Ahmed"))
        self.assertIsNone(self.db.get_user("Ahmed"))
        self.assertEqual(self.db.friend_lists("Omar")["friends"], [])

    def test_ban_and_password_change(self):
        self.db.add_user("Ahmed", "Str0ng!pass", "K")
        self.db.set_banned("Ahmed", True)
        self.assertEqual(self.db.get_user("Ahmed")["banned"], 1)
        self.db.set_password("Ahmed", "N3w!password")
        self.assertTrue(database.check_password("N3w!password", self.db.get_user("Ahmed")["pw_hash"]))

    def test_settings_whitelist(self):
        self.assertEqual(self.db.get_settings()["registration_open"], "1")
        self.db.set_setting("registration_open", "0")
        self.assertEqual(self.db.get_settings()["registration_open"], "0")
        with self.assertRaises(KeyError):
            self.db.set_setting("evil_key", "1")

    def test_events_and_audit_are_recorded(self):
        self.db.log_event("failed_login", "Ahmed", "127.0.0.1", "attempt 1")
        self.db.audit("root", "ban", "Ahmed")
        self.assertEqual(self.db.recent_events(username="Ahmed")[0]["kind"], "failed_login")
        self.assertEqual(self.db.audit_log()[0]["action"], "ban")

    def test_upgrade_from_first_version_schema(self):
        """A users.db created by the first version (no last_login/banned columns) still opens."""
        self.db.close()
        old = os.path.join(self.tmp, "old.db")
        import sqlite3
        con = sqlite3.connect(old)
        con.execute("CREATE TABLE users (username TEXT PRIMARY KEY COLLATE NOCASE, pw_hash TEXT NOT NULL, "
                    "public_key TEXT NOT NULL, created REAL NOT NULL)")
        con.execute("INSERT INTO users VALUES ('Old', 'h', 'k', 1)")
        con.commit()
        con.close()
        self.db = UserDB(old)
        self.assertEqual(self.db.get_user("Old")["banned"], 0)


if __name__ == "__main__":
    unittest.main()
