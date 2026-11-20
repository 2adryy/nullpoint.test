"""Tests for the presentation demos (Plain mode, MITM proxy, hacked server) and file sending."""

import http.client
import os
import socket
import struct
import threading
import unittest
from unittest import mock

from tests.helpers import PASSWORD, ServerTestCase
from securechat import mitm_proxy, web_client
from securechat.client_core import MAX_FILE_BYTES, ChatError, safe_filename


class MitmMixin:
    """Run the demo MITM proxy in a thread and record everything it prints."""

    def start_proxy(self, tamper=False):
        self.proxy_output = []
        patcher = mock.patch.object(mitm_proxy, "say", side_effect=self.proxy_output.append)
        patcher.start()
        self.addCleanup(patcher.stop)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        self.addCleanup(sock.close)

        def loop():
            while True:
                try:
                    client, addr = sock.accept()
                except OSError:
                    return
                mitm_proxy.handle(client, addr, ("127.0.0.1", self.server.port), tamper)

        threading.Thread(target=loop, daemon=True).start()
        return sock.getsockname()[1]

    def seen(self):
        return "\n".join(self.proxy_output)


# ============================================================ Plain demo mode

class PlainRefusedTests(ServerTestCase):
    def test_plain_mode_refused_by_default(self):
        with self.assertRaisesRegex(ChatError, "--allow-plain"):
            self.connected(plain=True)


class PlainModeTests(MitmMixin, ServerTestCase):
    SERVER_KWARGS = {"allow_plain": True}

    def test_plain_chat_works_but_is_marked_unencrypted(self):
        a, b = self.pair(plain_a=True, plain_b=True)
        sent = a.send_text("Omar", "hello in plain")
        self.assertFalse(sent["encrypted"])
        msg = b.wait_for("message")
        self.assertEqual(msg["text"], "hello in plain")
        self.assertFalse(msg["encrypted"])

    def test_secure_user_refuses_plain_messages(self):
        a, b = self.pair(plain_a=True, plain_b=False)
        a.send_text("Omar", "unsigned text")
        self.assertIn("unencrypted", b.wait_for("security")["text"])

    def test_sniffer_reads_password_and_message_in_plain_mode(self):
        port = self.start_proxy()
        a, b = self.pair(plain_a=True, plain_b=True, port_a=port)
        a.send_text("Omar", "my secret plan")
        b.wait_for("message")
        self.assertIn(PASSWORD, self.seen())
        self.assertIn("my secret plan", self.seen())

    def test_sniffer_sees_nothing_in_secure_mode(self):
        port = self.start_proxy()
        a, b = self.pair(port_a=port)
        a.send_text("Omar", "my secret plan")
        b.wait_for("message")
        self.assertNotIn(PASSWORD, self.seen())
        self.assertNotIn("my secret plan", self.seen())
        self.assertIn("ENCRYPTED", self.seen())

    def test_tamper_proxy_silently_changes_plain_messages(self):
        port = self.start_proxy(tamper=True)
        a, b = self.pair(plain_a=True, plain_b=True, port_a=port)
        a.send_text("Omar", "meet at 5pm")
        msg = b.wait_for("message")
        self.assertIn("CHANGED BY ATTACKER", msg["text"])   # nobody noticed: no integrity in plain mode

    def test_tamper_proxy_is_detected_in_secure_mode(self):
        port = self.start_proxy(tamper=True)
        a, b = self.pair(port_a=port)
        a.send_text("Omar", "meet at 5pm")
        a.wait_for("disconnected")                         # AES-GCM caught it: connection dropped
        self.assertIn("TAMPERED", self.seen())
        with self.assertRaises(AssertionError):
            b.wait_for("message", timeout=1)               # the changed message never arrived


# ============================================================ hacked server

class TamperServerTests(ServerTestCase):
    SERVER_KWARGS = {"attack": "tamper", "allow_plain": True}

    def test_tampered_encrypted_message_rejected(self):
        a, b = self.pair()
        a.send_text("Omar", "transfer 100")
        self.assertIn("Invalid signature", b.wait_for("security")["text"])

    def test_tampered_plain_message_goes_unnoticed(self):
        a, b = self.pair(plain_a=True, plain_b=True)
        a.send_text("Omar", "transfer 100")
        self.assertIn("HACKED SERVER", b.wait_for("message")["text"])

    def test_tampered_file_rejected(self):
        a, b = self.pair()
        a.send_file("Omar", "report.txt", b"secret numbers")
        self.assertIn("Invalid signature", b.wait_for("security")["text"])
        self.assertFalse(os.path.exists(f"{self.tmp}/omar/downloads"))


class ReplayServerTests(ServerTestCase):
    SERVER_KWARGS = {"attack": "replay"}

    def test_replayed_message_rejected(self):
        a, b = self.pair()
        a.send_text("Omar", "transfer 100 EGP")
        self.assertEqual(b.wait_for("message")["text"], "transfer 100 EGP")
        self.assertIn("replay", b.wait_for("security")["text"])

    def test_replayed_file_saved_once(self):
        a, b = self.pair()
        a.send_file("Omar", "a.txt", b"hello")
        b.wait_for("file")
        b.wait_for("security")
        self.assertEqual(os.listdir(f"{self.tmp}/omar/downloads/omar"), ["a.txt"])


# ============================================================ file sending

class FileTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.a, self.b = self.pair()

    def test_file_arrives_intact(self):
        data = os.urandom(200_000)
        sent = self.a.send_file("Omar", "photo.jpg", data)
        self.assertTrue(sent["encrypted"])
        info = self.b.wait_for("file")
        self.assertEqual(info["name"], "photo.jpg")
        self.assertTrue(info["encrypted"])
        with open(info["path"], "rb") as f:
            self.assertEqual(f.read(), data)
        self.assertEqual(self.server.stats["files"], 1)

    def test_send_from_disk_strips_folder(self):
        path = os.path.join(self.tmp, "my secret folder", "notes.txt")
        os.makedirs(os.path.dirname(path))
        with open(path, "wb") as f:
            f.write(b"notes")
        self.a.send_file_path("Omar", path)
        info = self.b.wait_for("file")
        self.assertEqual(info["name"], "notes.txt")

    def test_path_traversal_name_is_neutralized(self):
        self.a.send_file("Omar", "../../../../etc/evil.sh", b"rm -rf /")
        info = self.b.wait_for("file")
        downloads = os.path.realpath(f"{self.tmp}/omar/downloads/omar")
        self.assertEqual(os.path.dirname(os.path.realpath(info["path"])), downloads)
        self.assertEqual(info["name"], "evil.sh")

    def test_same_name_never_overwrites(self):
        for content in (b"first", b"second"):
            self.a.send_file("Omar", "report.txt", content)
        first, second = self.b.wait_for("file"), self.b.wait_for("file")
        self.assertEqual((first["name"], second["name"]), ("report.txt", "report (1).txt"))
        self.assertEqual(open(first["path"], "rb").read(), b"first")

    def test_limits(self):
        with self.assertRaisesRegex(ChatError, "too large"):
            self.a.send_file("Omar", "big.bin", b"x" * (MAX_FILE_BYTES + 1))
        with self.assertRaisesRegex(ChatError, "empty"):
            self.a.send_file("Omar", "empty.txt", b"")

    def test_largest_allowed_file(self):
        data = os.urandom(MAX_FILE_BYTES)
        self.a.send_file("Omar", "max.bin", data)
        info = self.b.wait_for("file", timeout=30)
        self.assertEqual(os.path.getsize(info["path"]), MAX_FILE_BYTES)

    def test_safe_filename(self):
        cases = {"a/b/c.txt": "c.txt", "..\\..\\x.exe": "x.exe", "": "file", "...": "file",
                 "hello <b>.html": "hello _b_.html", 'q"uote.txt': "q_uote.txt", "ملف.pdf": "___.pdf"}
        for raw, expected in cases.items():
            self.assertEqual(safe_filename(raw), expected, raw)


class FrameLimitTests(ServerTestCase):
    def test_big_frame_before_login_is_refused(self):
        """Only small frames are accepted before login, so strangers can't flood the server."""
        sock = socket.create_connection(("127.0.0.1", self.server.port), timeout=5)
        self.addCleanup(sock.close)
        header = sock.recv(5)
        length = struct.unpack(">I", header[:4])[0]
        while length - 1 > 0:
            length -= len(sock.recv(length - 1))
        sock.sendall(struct.pack(">IB", 200_000, ord("P")))   # announce a 200 KB frame
        sock.settimeout(5)
        self.assertEqual(sock.recv(10), b"")                  # server hung up


class DownloadTests(unittest.TestCase):
    def test_download_is_forced_attachment(self):
        """A received .html must download, never render inside the app (XSS through files)."""
        import tempfile
        from http.server import ThreadingHTTPServer
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "evil.html")
        with open(path, "w") as f:
            f.write("<script>alert(1)</script>")
        session = web_client.Session(tmp, "127.0.0.1", 1)
        session.files["abc"] = path
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
        port = httpd.server_port
        httpd.RequestHandlerClass = web_client.make_handler(session, "tok", port)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)

        def get(path):
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            c.request("GET", path, headers={"Host": f"127.0.0.1:{port}"})
            r = c.getresponse()
            body = r.read()
            c.close()
            return r, body

        r, body = get("/api/file?id=abc&token=tok")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("Content-Type"), "application/octet-stream")
        self.assertTrue(r.getheader("Content-Disposition").startswith("attachment"))
        self.assertIn("sandbox", r.getheader("Content-Security-Policy"))
        self.assertEqual(body, b"<script>alert(1)</script>")
        self.assertEqual(get("/api/file?id=abc&token=wrong")[0].status, 403)
        self.assertEqual(get("/api/file?id=nope&token=tok")[0].status, 404)


if __name__ == "__main__":
    unittest.main()
