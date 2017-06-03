"""
All cryptography for Dispersy.
"""
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import SECT233K1, SECT409K1, SECT571R1, generate_private_key, ECDSA
from cryptography.hazmat.primitives.hashes import SHA256, SHA512, SHA384, Hash, SHA1
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_der_public_key, Encoding, \
    load_pem_private_key, load_der_private_key, PublicFormat, PrivateFormat, BestAvailableEncryption, NoEncryption

DEFAULT_SECURITY_LEVELS = {"low": SECT233K1,
                           "medium": SECT409K1,
                           "high": SECT571R1}


class DispersyCrypto:
    """
    Cryptography helper methods for Dispersy.
    """
    @staticmethod
    def is_valid_public_key(string):
        """
        Verify if this binary string contains a public key.

        :param string: a byte string possibly containing a public key
        :return: a boolean
        """
        for encoding in ["PEM", "DER"]:
            try:
                DispersyPublicKey.from_bytes(string, encoding)
                return True
            except (ValueError, UnsupportedAlgorithm):
                pass

        return False

    @staticmethod
    def is_valid_private_key(string):
        """
        Verify if this binary string contains a public/private keypair.

        :param string: a byte string possible containing a private key
        :return: a boolean
        """
        for encoding in DispersyKey.ENCODINGS:
            try:
                DispersyPrivateKey.from_bytes(string, encoding)
                return True
            except (ValueError, UnsupportedAlgorithm):
                pass

        return False


class DispersyKey(object):
    """
    A wrapper around a key (pair).
    """
    ENCODINGS = {"DER", "PEM"}
    HASH_ALGORITHMS = {"SHA1": SHA1,
                       "SHA256": SHA256,
                       "SHA384": SHA384,
                       "SHA512": SHA512}

    def __init__(self, key):
        """
        Create a new DispersyPublicKey instance.

        :param key: an EllipticCurve instance
        """
        self.key = key

    @property
    def curve(self):
        """
        The curve instance by which the key is backed.

        :return: a
        """
        return self.key.curve

    @property
    def curve_name(self):
        """
        The name of the curve backing the key instance.

        :return: a string
        """
        return self.key.curve.name

    def has_private_key(self):
        """
        Whether this is a DispersyPublicKey or DispersyPrivateKey instance.

        :return: a boolean
        """
        raise NotImplementedError()

    def hash(self, hash_algorithm="SHA1"):
        """
        Get a hash of the public part of this key.

        :param hash_algorithm: one of HASH_ALGORITHMS
        :return: a binary string
        """
        digest = Hash(self.HASH_ALGORITHMS[hash_algorithm](), default_backend())
        digest.update(self.public_bytes())
        return digest.finalize()

    @property
    def key_size(self):
        return self.key.curve.key_size

    @property
    def signature_length(self):
        """
        TODO: Determine the signature length. See conversion.py, L1111.

        These seem somehow longer than expected. For example: 233 bits -> 60 bytes, but actually is 64 bytes.
        :return:
        """
        temporary_key = generate_private_key(self.curve, default_backend())
        signature = temporary_key.sign(b"", ECDSA(SHA1()))
        return len(signature)

    def public_bytes(self, encoding="PEM", encoding_format="SubjectPublicKeyInfo"):
        """
        Get this public key in byte form.

        :param encoding: either "PEM" or "DER"
        :param encoding_format: either "X.509 subjectPublicKeyInfo with PKCS#1", "Raw PKCS#1" or "OpenSSH"
        :return: a byte string
        """
        return self.key.public_bytes(Encoding[encoding], PublicFormat[encoding_format])

    @staticmethod
    def verify(key, signature, data, hash_algorithm="SHA1"):
        """
        Verify whether the data was signed for this public key.

        :param key: a public key to check against
        :param signature: a bytes object with DER encoded contents (See RFC 3279)
        :param data: the signed data
        :param hash_algorithm: the hash algorithm used in signing
        :return: a boolean
        """
        algorithm = ECDSA(DispersyKey.HASH_ALGORITHMS[hash_algorithm]())
        try:
            key.verify(signature, data, algorithm)
        except InvalidSignature:
            return False
        return True


class DispersyPublicKey(DispersyKey):
    """
    A wrapper around a public key.
    """
    AVAILABLE_FORMATS = PublicFormat.__members__.keys()

    def __init__(self, key):
        """
        Create a new DispersyPublicKey instance.

        :param key: an EllipticCurvePublicKey instance
        """
        super(DispersyPublicKey, self).__init__(key)
        self.public_key = self

    def public_bytes(self, encoding="PEM", encoding_format="SubjectPublicKeyInfo"):
        return self.key.public_bytes(Encoding[encoding], PublicFormat[encoding_format])

    @property
    def has_private_key(self):
        return False

    def verify(self, signature, data, hash_algorithm="SHA1"):
        return DispersyKey.verify(self.key, signature, data, hash_algorithm)

    @staticmethod
    def from_bytes(string, encoding="PEM"):
        """
        Load a DispersyPublicKey from a byte string.

        :param string: the byte string containing the public key
        :param encoding: the encoding used. One of "PEM" or "DER"
        :return: a new DispersyPublicKey instance
        """
        if Encoding[encoding] is Encoding.PEM:
            loaded_key = load_pem_public_key(string, backend=default_backend())
        elif Encoding[encoding] is Encoding.DER:
            loaded_key = load_der_public_key(string, backend=default_backend())
        else:
            raise UnknownKeyEncodingException(encoding)

        return DispersyPublicKey(loaded_key)


class DispersyPrivateKey(DispersyKey):
    """
    A wrapper around a key pair.
    """
    AVAILABLE_FORMATS = PrivateFormat.__members__.keys()

    def __init__(self, key=None, security_level="high"):
        """
        Create a new private-public key pair.

        :param key: the private key
        :param security_level: a curve to generate a new key from, if one is not provided
        """
        key = key or generate_private_key(DEFAULT_SECURITY_LEVELS[security_level], backend=default_backend())
        super(DispersyPrivateKey, self).__init__(key)

        self.public_key = DispersyPublicKey(self.key.public_key())

    def public_bytes(self, encoding="PEM", encoding_format="SubjectPublicKeyInfo"):
        return self.public_key.public_bytes(encoding, encoding_format)

    def private_bytes(self, encoding="PEM", encoding_format="PKCS8", password=None):
        """
        Get this private key in byte form.

        :param encoding: either "PEM" or "DER"
        :param encoding_format: either "X.509 subjectPublicKeyInfo with PKCS#1", "Raw PKCS#1" or "OpenSSH"
        :param password: an optional password in case the private key is to be encoded
        :return: a byte string
        """
        encryption = BestAvailableEncryption(password) if password else NoEncryption()
        return self.key.private_bytes(Encoding[encoding], PrivateFormat[encoding_format], encryption)

    @property
    def has_private_key(self):
        return True

    def sign(self, data, hash_algorithm="SHA1"):
        """
        Sign the provided data.

        Note that in order to verify the signature created by this method, the
        hash algorithm used in creating the signature needs to be known. It is
        therefore advised not to deviate from the default algorithm.

        :param data: the data to sign
        :param hash_algorithm: the hash algorithm to use in signing
        :return: a bytes object with DER encoded contents (see RFC 3279)
        """
        algorithm = ECDSA(self.HASH_ALGORITHMS[hash_algorithm]())
        return self.key.sign(data, algorithm)

    def verify(self, signature, data, hash_algorithm="SHA1"):
        return DispersyKey.verify(self.key.public_key(), signature, data, hash_algorithm)

    @staticmethod
    def from_bytes(string, encoding="PEM", password=None):
        """
        Load a private key from a byte string.

        :param string: the byte string containing the private key
        :param encoding: the encoding used
        :param password: an optional password in case the private key is encoded
        :return: a new DispersyPrivateKey instance
        """
        if Encoding[encoding] is Encoding.PEM:
            loaded_key = load_pem_private_key(string, password=password, backend=default_backend())
        elif Encoding[encoding] is Encoding.DER:
            loaded_key = load_der_private_key(string, password=password, backend=default_backend())
        else:
            raise UnknownKeyEncodingException(encoding)

        return DispersyPrivateKey(loaded_key)


class UnknownKeyEncodingException(Exception):
    """
    Thrown when a key encoding wasn't recognised.
    """
    pass
