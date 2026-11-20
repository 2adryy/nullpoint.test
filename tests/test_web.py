"""Security tests for the two web front ends: the user's local page and the admin page."""

import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer

from tests.helpers import PASSWORD, ServerTestCase
from securechat import admin_web, web_client


def request(port, method, path, body=None, headers=None, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {"Host": host or f"127.0.0.1:{port}"}
    h.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=data, headers=h)
    res = conn.getresponse()
    raw = res.read()
    conn.close()
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw.decode("utf-8", "replace")
    return res.status, payload, res


def serve(make):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), None)
    httpd.RequestHandlerClass = make(httpd.server_port)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


class UserWebTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.session = web_client.Session(f"{self.tmp}/web", "127.0.0.1", self.server.port)
        self.token = "test-token-123"
        self.httpd = serve(lambda port: web_client.make_handler(self.session, self.token, port))
        self.port = self.httpd.server_port
        self.auth = {"X-SecureChat-Token": self.token}

    def tearDown(self):
        self.session.logout()
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def test_page_has_token_and_security_headers(self):
        status, html, res = request(self.port, "GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(self.token, html)
        csp = res.getheader("Content-Security-Policy")
        self.assertIn("script-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertEqual(res.getheader("X-Frame-Options"), "DENY")

    def test_api_requires_token(self):
        self.assertEqual(request(self.port, "GET", "/api/state")[0], 403)
        self.assertEqual(request(self.port, "GET", "/api/state", headers={"X-SecureChat-Token": "wrong"})[0], 403)
        self.assertEqual(request(self.port, "GET", "/api/state", headers=self.auth)[0], 200)
        # CSRF: a POST from another website has no token
        self.assertEqual(request(self.port, "POST", "/api/send", {"to": "x", "text": "y"})[0], 403)

    def test_dns_rebinding_blocked(self):
        self.assertEqual(request(self.port, "GET", "/", host="evil.example:80")[0], 403)

    def test_path_traversal_blocked(self):
        for path in ("/static/../web_client.py", "/static/..%2Fweb_client.py", "/static/.hidden"):
            self.assertEqual(request(self.port, "GET", path)[0], 404, path)

    def test_post_needs_json(self):
        status, _, _ = request(self.port, "POST", "/api/logout", body={},
                               headers={**self.auth, "Content-Type": "text/plain"})
        self.assertEqual(status, 415)

    def test_register_login_and_state_through_api(self):
        status, res, _ = request(self.port, "POST", "/api/login",
                                 {"username": "Ahmed", "password": PASSWORD, "host": "127.0.0.1",
                                  "port": self.server.port, "register": True}, self.auth)
        self.assertTrue(res["ok"], res)
        _, state, _ = request(self.port, "GET", "/api/state", headers=self.auth)
        self.assertTrue(state["logged_in"])
        self.assertEqual(state["username"], "Ahmed")
        self.assertNotIn("PRIVATE KEY", json.dumps(state))   # the browser never gets the private key
        _, res, _ = request(self.port, "POST", "/api/friend_add", {"name": "Ghost"}, self.auth)
        self.assertFalse(res["ok"])

    def test_bad_port_rejected(self):
        _, res, _ = request(self.port, "POST", "/api/login",
                            {"username": "A", "password": "p", "host": "h", "port": 99999}, self.auth)
        self.assertIn("Port", res["error"])


class AdminWebTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.server.db.add_admin("root", "Adm1n!pass")
        self.httpd = serve(lambda port: admin_web.make_handler(self.server, admin_web.AdminSessions(), port))
        self.port = self.httpd.server_port
        self.csrf = {"X-SecureChat-Admin": "1"}

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        super().tearDown()

    def login(self, password="Adm1n!pass"):
        status, res, raw = request(self.port, "POST", "/api/login",
                                   {"username": "root", "password": password}, self.csrf)
        cookie = raw.getheader("Set-Cookie") or ""
        return res, cookie

    def cookie_header(self, cookie):
        return {"Cookie": cookie.split(";")[0], **self.csrf}

    def test_dashboard_requires_login(self):
        self.assertEqual(request(self.port, "GET", "/api/dashboard")[0], 401)

    def test_login_sets_safe_cookie(self):
        res, cookie = self.login()
        self.assertTrue(res["ok"])
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        status, data, _ = request(self.port, "GET", "/api/dashboard", headers=self.cookie_header(cookie))
        self.assertEqual(status, 200)
        self.assertIn("stats", data)

    def test_wrong_password_and_lockout(self):
        for _ in range(5):
            res, cookie = self.login("Wr0ng!pass")
            self.assertFalse(res["ok"])
            self.assertEqual(cookie, "")
        res, _ = self.login()
        self.assertIn("Too many attempts", res["error"])
        self.assertEqual(self.server.db.recent_events(1)[0]["kind"], "admin_login_failed")

    def test_normal_user_cannot_log_in_as_admin(self):
        self.user("Ahmed")
        _, res, _ = request(self.port, "POST", "/api/login", {"username": "Ahmed", "password": PASSWORD}, self.csrf)
        self.assertFalse(res["ok"])

    def test_csrf_header_required(self):
        _, cookie = self.login()
        status, _, _ = request(self.port, "POST", "/api/announce", {"text": "hi"},
                               {"Cookie": cookie.split(";")[0]})
        self.assertEqual(status, 403)

    def test_actions_need_session(self):
        status, _, _ = request(self.port, "POST", "/api/ban", {"username": "Ahmed"}, self.csrf)
        self.assertEqual(status, 401)

    def test_admin_ban_through_api_is_audited(self):
        a = self.user("Ahmed")
        _, cookie = self.login()
        _, res, _ = request(self.port, "POST", "/api/ban", {"username": "Ahmed"}, self.cookie_header(cookie))
        self.assertTrue(res["ok"], res)
        a.wait_for("disconnected")
        audit = self.server.db.audit_log()
        self.assertEqual((audit[0]["admin"], audit[0]["action"], audit[0]["target"]), ("root", "ban", "Ahmed"))

    def test_logout_invalidates_session(self):
        _, cookie = self.login()
        request(self.port, "POST", "/api/logout", {}, self.cookie_header(cookie))
        self.assertEqual(request(self.port, "GET", "/api/dashboard", headers=self.cookie_header(cookie))[0], 401)

    def test_only_whitelisted_static_files(self):
        self.assertEqual(request(self.port, "GET", "/static/admin.js")[0], 200)
        self.assertEqual(request(self.port, "GET", "/static/index.html")[0], 404)
        self.assertEqual(request(self.port, "GET", "/static/../server.py")[0], 404)

    def test_dns_rebinding_blocked(self):
        self.assertEqual(request(self.port, "GET", "/", host="evil.example")[0], 403)


if __name__ == "__main__":
    unittest.main()
