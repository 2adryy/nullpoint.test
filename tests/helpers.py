"""Shared helpers: a real server on a random port, clients with an event queue,
temporary data folders (the tests never touch your real client_data/server_data)."""

import logging
import queue
import shutil
import tempfile
import time
import unittest

from securechat import database
from securechat.client_core import ChatClient
from securechat.server import ChatServer

# bcrypt cost 12 is deliberately slow; cost 4 keeps the test suite fast.
database.BCRYPT_ROUNDS = 4
logging.getLogger("securechat.server").setLevel(logging.CRITICAL)

PASSWORD = "Str0ng!pass"


class EventClient(ChatClient):
    """ChatClient that records every event so tests can wait for them."""

    def __init__(self, data_dir):
        self.events = queue.Queue()
        super().__init__(data_dir, on_event=lambda k, d: self.events.put((k, d)))

    def wait_for(self, kind, timeout=5.0, match=None):
        """Return the data of the next event of this kind (optionally matching a predicate)."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                k, d = self.events.get(timeout=0.1)
            except queue.Empty:
                continue
            if k == kind and (match is None or match(d)):
                return d
        raise AssertionError(f"timed out waiting for event '{kind}'")

    def drain(self):
        while not self.events.empty():
            self.events.get_nowait()


class ServerTestCase(unittest.TestCase):
    """Starts a fresh server (and temp folder) for every test."""

    SERVER_KWARGS: dict = {}   # e.g. {"allow_plain": True} or {"attack": "tamper"}

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="securechat-test-")
        self.server = ChatServer("127.0.0.1", 0, f"{self.tmp}/server", **self.SERVER_KWARGS)
        self.server.start()
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.logout()
        self.server.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def new_client(self, folder="client"):
        c = EventClient(f"{self.tmp}/{folder}")
        self.clients.append(c)
        return c

    def connected(self, folder="client", plain=False, port=None):
        c = self.new_client(folder)
        c.connect("127.0.0.1", port or self.server.port, plain=plain)
        return c

    def user(self, name, folder=None, plain=False, port=None):
        """Register + log in a user in its own folder; wait until the friends list arrives."""
        c = self.connected(folder or name.lower(), plain=plain, port=port)
        c.register(name, PASSWORD)
        c.login(name, PASSWORD)
        c.wait_for("friends")
        return c

    @staticmethod
    def friend_online(name):
        return lambda d: any(c["name"] == name and c["online"] for c in d["contacts"])

    def pair(self, plain_a=False, plain_b=False, port_a=None, port_b=None):
        """Two logged-in users who are friends and see each other online."""
        a = self.user("Ahmed", plain=plain_a, port=port_a)
        b = self.user("Omar", plain=plain_b, port=port_b)
        a.add_friend("Omar")
        b.wait_for("friends", match=lambda d: "Ahmed" in d["incoming"])
        b.respond_friend("Ahmed", True)
        a.wait_for("friends", match=self.friend_online("Omar"))
        b.wait_for("friends", match=self.friend_online("Ahmed"))
        return a, b
