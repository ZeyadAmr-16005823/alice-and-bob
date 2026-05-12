# =============================================================================
# rsa_decrypt.py
# Author  : Ahmed Bahaa
# Purpose : RSA signature verification and AES decryption
# =============================================================================

from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def verify(public_key, data: bytes, signature: bytes) -> bool:
    """
    Verify an RSA signature.

    Args:
        public_key : RsaKey — the sender's RSA public key
        data       : bytes  — the original signed data
        signature  : bytes  — the signature to verify

    Returns:
        True if valid, False otherwise
    """
    try:
        hash_obj = SHA256.new(data)
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False


def aes_decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt data using AES-EAX mode.

    Args:
        key        : bytes — the AES session key (derived from DH)
        ciphertext : bytes — the encrypted data
        nonce      : bytes — the nonce used during encryption
        tag        : bytes — the authentication tag

    Returns:
        plaintext as bytes
    """
    cipher    = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext