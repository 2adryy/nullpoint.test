"""Unit tests for crypto_utils: hybrid encryption, signatures, key storage, fingerprints."""

import copy
import re
import time
import unittest

from securechat import crypto_utils as cu


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice = cu.generate_private_key()
        cls.bob = cu.generate_private_key()
        cls.eve = cu.generate_private_key()

    def packet(self, text=b"secret report"):
        header = {"from": "alice", "to": "bob", "ts": time.time(), "id": "abc123", "kind": "text"}
        return cu.encrypt_message(self.alice, self.bob.public_key(), header, text)

    def test_round_trip(self):
        self.assertEqual(cu.decrypt_message(self.bob, self.alice.public_key(), self.packet()), b"secret report")

    def test_ciphertext_does_not_contain_plaintext(self):
        p = self.packet(b"very secret words")
        self.assertNotIn(b"very secret words", cu.b64d(p["ct"]))

    def test_each_message_uses_a_fresh_key_and_nonce(self):
        p1, p2 = self.packet(), self.packet()
        self.assertNotEqual(p1["ek"], p2["ek"])
        self.assertNotEqual(p1["nonce"], p2["nonce"])
        self.assertNotEqual(p1["ct"], p2["ct"])

    def test_tampered_ciphertext_rejected(self):
        p = self.packet()
        ct = bytearray(cu.b64d(p["ct"]))
        ct[0] ^= 1
        p["ct"] = cu.b64e(bytes(ct))
        with self.assertRaises(cu.CryptoError):
            cu.decrypt_message(self.bob, self.alice.public_key(), p)

    def test_tampered_header_rejected(self):
        for field, value in (("from", "eve"), ("to", "carol"), ("ts", 0), ("id", "other")):
            p = self.packet()
            p["header"][field] = value
            with self.subTest(field=field), self.assertRaises(cu.CryptoError):
                cu.decrypt_message(self.bob, self.alice.public_key(), p)

    def test_wrong_sender_key_rejected(self):
        """Eve signs a message claiming to be Alice: verification with Alice's key fails."""
        header = {"from": "alice", "to": "bob", "ts": time.time(), "id": "x", "kind": "text"}
        forged = cu.encrypt_message(self.eve, self.bob.public_key(), header, b"hi")
        with self.assertRaises(cu.CryptoError):
            cu.decrypt_message(self.bob, self.alice.public_key(), forged)

    def test_only_recipient_can_decrypt(self):
        with self.assertRaises(cu.CryptoError):
            cu.decrypt_message(self.eve, self.alice.public_key(), self.packet())

    def test_resigned_tampered_packet_still_fails_aes(self):
        """Even with a valid signature, changing the header breaks the AES-GCM AAD binding."""
        p = self.packet()
        p["header"]["id"] = "changed"
        p["sig"] = cu.b64e(cu.sign(self.alice, cu._signed_part(p)))
        with self.assertRaises(cu.CryptoError):
            cu.decrypt_message(self.bob, self.alice.public_key(), p)

    def test_malformed_packet_rejected(self):
        p = self.packet()
        for broken in ({k: v for k, v in p.items() if k != "sig"}, dict(p, ct="!!not base64!!")):
            with self.assertRaises(cu.CryptoError):
                cu.decrypt_message(self.bob, self.alice.public_key(), copy.deepcopy(broken))

    def test_private_key_encrypted_with_password(self):
        pem = cu.private_key_to_pem(self.alice, "Str0ng!pass")
        self.assertIn(b"ENCRYPTED", pem)
        loaded = cu.load_private_key(pem, "Str0ng!pass")
        self.assertEqual(cu.public_pem(loaded), cu.public_pem(self.alice))
        with self.assertRaises(cu.CryptoError):
            cu.load_private_key(pem, "wrong password")

    def test_fingerprint_format_and_uniqueness(self):
        fp = cu.fingerprint(cu.public_pem(self.alice))
        self.assertRegex(fp, r"^([0-9A-F]{4} ){7}[0-9A-F]{4}$")
        self.assertEqual(fp, cu.fingerprint(cu.public_pem(self.alice)))
        self.assertNotEqual(fp, cu.fingerprint(cu.public_pem(self.bob)))

    def test_weak_public_key_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        with self.assertRaises(cu.CryptoError):
            cu.load_public_key(cu.public_pem(small))

    def test_aes_gcm_aad_binding(self):
        key = cu.new_aes_key()
        nonce, ct = cu.aes_encrypt(key, b"data", b"aad-1")
        self.assertEqual(cu.aes_decrypt(key, nonce, ct, b"aad-1"), b"data")
        with self.assertRaises(cu.CryptoError):
            cu.aes_decrypt(key, nonce, ct, b"aad-2")

    def test_base64_is_not_encryption_but_round_trips(self):
        self.assertEqual(cu.b64d(cu.b64e(b"\x00\xffabc")), b"\x00\xffabc")
        self.assertTrue(re.fullmatch(r"[A-Za-z0-9+/=]+", cu.b64e(b"hello")))


if __name__ == "__main__":
    unittest.main()
