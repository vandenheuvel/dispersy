from unittest import TestCase

from ..crypto import DispersyPrivateKey, DEFAULT_SECURITY_LEVELS, DispersyPublicKey


class TestDispersyKey(TestCase):

    def setUp(self):
        self.data = "".join(chr(i % 256) for i in range(1024))

    def test_sign_and_verify(self):
        """
        Creates a curve for each security_level, signs some data, and finally verifies the signature.
        """
        for security_level in DEFAULT_SECURITY_LEVELS.keys():
            key = DispersyPrivateKey(security_level=security_level)
            signature = key.sign(self.data)

            self.assertTrue(key.verify(signature, self.data))

    def test_serialise_private(self):
        """
        Create, serialise and deserialize a key for each curve.
        """
        for security_level in DEFAULT_SECURITY_LEVELS.keys():
            key = DispersyPrivateKey(security_level=security_level)
            binary = key.private_bytes()
            key2 = DispersyPrivateKey.from_bytes(binary)

            self.assertEqual(key2.hash(), key.hash())

    def test_serialise_public(self):
        """
        Creates and serialises each curve.
        """
        for security_level in DEFAULT_SECURITY_LEVELS.keys():
            key = DispersyPrivateKey(security_level=security_level)
            public_key = key.public_key
            signature = key.sign(self.data)

            binary = public_key.public_bytes()
            key2 = DispersyPublicKey.from_bytes(binary)

            self.assertTrue(key2.verify(signature, self.data))

    def test_sign_not_valid(self):
        """
        A signature created with another key shouldn't be valid.
        """
        for security_level in DEFAULT_SECURITY_LEVELS.keys():
            key1 = DispersyPrivateKey(security_level=security_level)
            key2 = DispersyPrivateKey(security_level=security_level)
            signature1 = key1.sign(self.data)
            signature2 = key2.sign(self.data)

            self.assertFalse(key1.verify(signature2, self.data))
            self.assertFalse(key2.verify(signature1, self.data))

    def test_sign_verify_with_public(self):
        """
        Signature verification should be possible with a public key only.
        """
        for security_level in DEFAULT_SECURITY_LEVELS.keys():
            key = DispersyPrivateKey(security_level=security_level)
            public_key = key.public_key
            signature = key.sign(self.data)

            self.assertTrue(public_key.verify(signature, self.data))

    def test_sign_verify_with_other_public(self):
        """
        Signature verification with another public key should fail.
        """
        for security_level in DEFAULT_SECURITY_LEVELS.keys():
            key1 = DispersyPrivateKey(security_level=security_level)
            key2 = DispersyPrivateKey(security_level=security_level)
            public_key1 = key1.public_key
            public_key2 = key2.public_key
            signature1 = key1.sign(self.data)
            signature2 = key2.sign(self.data)

            self.assertFalse(public_key1.verify(signature2, self.data))
            self.assertFalse(public_key2.verify(signature1, self.data))

    def test_hash(self):
        """
        Test taking a hash.
        """
        key = DispersyPrivateKey()
        h = key.hash()
        self.assertEqual(len(h), 20)

        public_key = key.public_key
        h = key.hash()
        self.assertEqual(len(h), 20)
