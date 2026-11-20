"""Unit tests for protocol.Channel: framing and the encrypted channel (replay/tamper)."""

import socket
import struct
import unittest

from securechat import crypto_utils as cu
from securechat.protocol import MAX_FRAME, Channel, ProtocolError


class ChannelTests(unittest.TestCase):
    def setUp(self):
        a, b = socket.socketpair()
        a.settimeout(5)
        b.settimeout(5)
        self.client = Channel(a, is_client=True)
        self.server = Channel(b, is_client=False)

    def tearDown(self):
        self.client.close()
        self.server.close()

    def encrypt_both(self):
        key = cu.new_aes_key()
        self.client.enable_encryption(key)
        self.server.enable_encryption(key)

    def raw_frames(self, n):
        """Capture the next n frames the client sends, as raw bytes."""
        frames = []
        for _ in range(n):
            header = self.server.sock.recv(5, socket.MSG_WAITALL)
            length = struct.unpack(">I", header[:4])[0]
            frames.append(header + self.server.sock.recv(length - 1, socket.MSG_WAITALL))
        return frames

    def test_plain_round_trip(self):
        self.client.send({"type": "hello", "x": 1})
        self.assertEqual(self.server.recv(), {"type": "hello", "x": 1})

    def test_encrypted_round_trip_both_directions(self):
        self.encrypt_both()
        self.client.send({"type": "ping", "text": "hi"})
        self.assertEqual(self.server.recv()["text"], "hi")
        self.server.send({"type": "pong"})
        self.assertEqual(self.client.recv()["type"], "pong")

    def test_encrypted_frames_hide_content(self):
        self.encrypt_both()
        self.client.send({"type": "login", "password": "Str0ng!pass"})
        frame = self.raw_frames(1)[0]
        self.assertEqual(frame[4:5], b"S")
        self.assertNotIn(b"Str0ng!pass", frame)
        self.assertNotIn(b"login", frame)

    def test_replayed_frame_rejected(self):
        self.encrypt_both()
        self.client.send({"type": "a"})
        frame = self.raw_frames(1)[0]
        self.client.sock.sendall(frame)          # first delivery: OK
        self.assertEqual(self.server.recv()["type"], "a")
        self.client.sock.sendall(frame)          # same bytes again: counter mismatch
        with self.assertRaises(ProtocolError):
            self.server.recv()

    def test_reordered_frames_rejected(self):
        self.encrypt_both()
        self.client.send({"type": "first"})
        self.client.send({"type": "second"})
        f1, f2 = self.raw_frames(2)
        self.client.sock.sendall(f2 + f1)
        with self.assertRaises(ProtocolError):
            self.server.recv()

    def test_modified_frame_rejected(self):
        self.encrypt_both()
        self.client.send({"type": "a"})
        frame = bytearray(self.raw_frames(1)[0])
        frame[-1] ^= 1
        self.client.sock.sendall(bytes(frame))
        with self.assertRaises(ProtocolError):
            self.server.recv()

    def test_reflected_frame_rejected(self):
        """A frame the server sent cannot be bounced back to it (direction tag in AAD)."""
        self.encrypt_both()
        self.server.send({"type": "x"})
        header = self.client.sock.recv(5, socket.MSG_WAITALL)
        length = struct.unpack(">I", header[:4])[0]
        frame = header + self.client.sock.recv(length - 1, socket.MSG_WAITALL)
        self.client.sock.sendall(frame)
        with self.assertRaises(ProtocolError):
            self.server.recv()

    def test_plain_frame_after_encryption_rejected(self):
        self.encrypt_both()
        payload = b'{"type": "evil"}'
        self.client.sock.sendall(struct.pack(">IB", len(payload) + 1, ord("P")) + payload)
        with self.assertRaises(ProtocolError):
            self.server.recv()

    def test_oversized_and_empty_lengths_rejected(self):
        for length in (0, MAX_FRAME + 1):
            a, b = socket.socketpair()
            ch = Channel(b, is_client=False)
            a.sendall(struct.pack(">IB", length, ord("P")))
            with self.subTest(length=length), self.assertRaises(ProtocolError):
                ch.recv()
            a.close()
            ch.close()

    def test_invalid_json_rejected(self):
        for payload in (b"not json", b"[1,2,3]", b'{"no_type": 1}'):
            self.client.sock.sendall(struct.pack(">IB", len(payload) + 1, ord("P")) + payload)
            with self.subTest(payload=payload), self.assertRaises(ProtocolError):
                self.server.recv()

    def test_closed_connection_raises(self):
        self.client.close()
        with self.assertRaises(ConnectionError):
            self.server.recv()


if __name__ == "__main__":
    unittest.main()
