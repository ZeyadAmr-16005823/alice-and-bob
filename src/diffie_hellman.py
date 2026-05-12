# =============================================================================
# diffie_hellman.py
# Author  : Youssef Hassan
# Purpose : Diffie-Hellman key exchange, KDF, and AES encryption
# =============================================================================

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import random


# DH public parameters — shared between Alice and Bob (RFC 3526, 2048-bit MODP group)
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22"
    "514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5"
    "AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A"
    "69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E8603"
    "9B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE5"
    "15D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    16
)
DH_GENERATOR = 2


def generate_dh_private_key() -> int:
    """
    Generate a random DH private key.

    Returns:
        A random integer to use as the DH private key
    """
    return random.randint(2, DH_PRIME - 2)


def generate_dh_public_key(private_key: int) -> int:
    """
    Compute the DH public key: g^private_key mod p

    Args:
        private_key : int — the DH private key

    Returns:
        DH public key as int
    """
    return pow(DH_GENERATOR, private_key, DH_PRIME)


def compute_shared_secret(their_public_key: int, my_private_key: int) -> int:
    """
    Compute the DH shared secret: their_public^my_private mod p

    Args:
        their_public_key : int — the other party's DH public key
        my_private_key   : int — our DH private key

    Returns:
        shared secret as int
    """
    return pow(their_public_key, my_private_key, DH_PRIME)


def derive_session_key(shared_secret: int, key_length: int = 32) -> bytes:
    """
    Derive a symmetric AES key from the DH shared secret using a KDF.

    Args:
        shared_secret : int — the raw DH shared secret
        key_length    : int — desired key size in bytes (16, 24, or 32 for AES)

    Returns:
        AES key as bytes
    """
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    salt         = b'alice-and-bob-salt'
    session_key  = PBKDF2(secret_bytes, salt, dkLen=key_length, count=1000, hmac_hash_module=SHA256)
    return session_key


def aes_encrypt(key: bytes, plaintext: bytes):
    """
    Encrypt data using AES-EAX mode.

    Args:
        key       : bytes — the AES session key
        plaintext : bytes — data to encrypt

    Returns:
        (ciphertext, nonce, tag) as bytes
    """
    cipher              = AES.new(key, AES.MODE_EAX)
    ciphertext, tag     = cipher.encrypt_and_digest(plaintext)
    return ciphertext, cipher.nonce, tag