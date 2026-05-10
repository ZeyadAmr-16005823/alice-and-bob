# =============================================================================
# rsa_encrypt.py
# Author  : Ziad Amr
# Purpose : RSA key pair generation and digital signing
# =============================================================================

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def generate_rsa_keypair(bits: int = 2048):
    """
    Generate an RSA key pair.

    Args:
        bits: Key size in bits (default 2048)

    Returns:
        (private_key, public_key) as RsaKey objects
    """
    # TODO: Generate RSA key pair using Crypto.PublicKey.RSA
    pass


def sign(private_key, data: bytes) -> bytes:
    """
    Sign data using an RSA private key.

    Args:
        private_key : RsaKey — the signer's RSA private key
        data        : bytes  — the data to sign (e.g. a DH public value)

    Returns:
        signature as bytes
    """
    # TODO: Hash the data with SHA256, then sign with pkcs1_15
    pass
