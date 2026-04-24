""" symenc.py
"""
from cryptography.exceptions import UnsupportedAlgorithm

from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

from .errors import PGPDecryptionError
from .errors import PGPEncryptionError
from .errors import PGPInsecureCipherError

__all__ = ['_encrypt',
           '_decrypt']


def _encrypt(pt, key, alg, iv=None):
    raise NotImplementedError


def _decrypt(ct, key, alg, iv=None):
    raise NotImplementedError
