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
    # TODO: Hash data with SHA256, verify with pkcs1_15
    # Catch ValueError if verification fails and return False
    pass


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
    # TODO: Use AES.new() in MODE_EAX with the provided nonce
    # Decrypt and verify the tag — raise ValueError if tampered
    pass
