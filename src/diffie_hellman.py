# =============================================================================
# diffie_hellman.py
# Author  : Youssef Hassan
# Purpose : Diffie-Hellman key exchange, KDF, and AES encryption
# =============================================================================

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# DH public parameters — shared between Alice and Bob
DH_PRIME = (
    0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
    020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
    4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05
    98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB
    9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
    E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
    3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
)
DH_GENERATOR = 2


def generate_dh_private_key() -> int:
    """
    Generate a random DH private key.

    Returns:
        A random integer to use as the DH private key
    """
    # TODO: Generate a secure random integer less than DH_PRIME
    pass


def generate_dh_public_key(private_key: int) -> int:
    """
    Compute the DH public key: g^private_key mod p

    Args:
        private_key : int — the DH private key

    Returns:
        DH public key as int
    """
    # TODO: Return DH_GENERATOR ** private_key % DH_PRIME
    pass


def compute_shared_secret(their_public_key: int, my_private_key: int) -> int:
    """
    Compute the DH shared secret: their_public^my_private mod p

    Args:
        their_public_key : int — the other party's DH public key
        my_private_key   : int — our DH private key

    Returns:
        shared secret as int
    """
    # TODO: Return their_public_key ** my_private_key % DH_PRIME
    pass


def derive_session_key(shared_secret: int, key_length: int = 32) -> bytes:
    """
    Derive a symmetric AES key from the DH shared secret using a KDF.

    Args:
        shared_secret : int — the raw DH shared secret
        key_length    : int — desired key size in bytes (16, 24, or 32 for AES)

    Returns:
        AES key as bytes
    """
    # TODO: Convert shared_secret to bytes, then apply PBKDF2 with SHA256
    # Use a fixed salt for reproducibility (both parties must derive the same key)
    pass


def aes_encrypt(key: bytes, plaintext: bytes):
    """
    Encrypt data using AES-EAX mode.

    Args:
        key       : bytes — the AES session key
        plaintext : bytes — data to encrypt

    Returns:
        (ciphertext, nonce, tag) as bytes
    """
    # TODO: Use AES.new() in MODE_EAX, encrypt and return ciphertext, nonce, tag
    pass
