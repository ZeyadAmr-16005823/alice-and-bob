# =============================================================================
# key_manager.py
# Author  : Marawan Elgendy
# Purpose : RSA key serialization, storage, and exchange between Alice & Bob
# =============================================================================

from Crypto.PublicKey import RSA
import os

KEYS_DIR = os.path.join(os.path.dirname(__file__), "../keys")


def save_private_key(private_key, filename: str):
    """
    Serialize and save an RSA private key to a .pem file.

    Args:
        private_key : RsaKey — the RSA private key to save
        filename    : str    — output filename (e.g. 'alice_private.pem')
    """
    # TODO: Export private key as PEM and write to keys/ directory
    pass


def save_public_key(public_key, filename: str):
    """
    Serialize and save an RSA public key to a .pem file.

    Args:
        public_key : RsaKey — the RSA public key to save
        filename   : str    — output filename (e.g. 'alice_public.pem')
    """
    # TODO: Export public key as PEM and write to keys/ directory
    pass


def load_private_key(filename: str):
    """
    Load an RSA private key from a .pem file.

    Args:
        filename : str — the .pem file to load (from keys/ directory)

    Returns:
        RsaKey object
    """
    # TODO: Read PEM file and import with RSA.import_key()
    pass


def load_public_key(filename: str):
    """
    Load an RSA public key from a .pem file.

    Args:
        filename : str — the .pem file to load (from keys/ directory)

    Returns:
        RsaKey object
    """
    # TODO: Read PEM file and import with RSA.import_key()
    pass


def setup_keys(generate_keypair_fn):
    """
    Generate and save RSA key pairs for both Alice and Bob.

    Args:
        generate_keypair_fn : callable — the generate_rsa_keypair function from rsa_encrypt.py

    Returns:
        (alice_private, alice_public, bob_private, bob_public)
    """
    # TODO: Create keys/ directory if it doesn't exist
    # Generate keypairs for Alice and Bob
    # Save all four keys to the keys/ directory
    # Return all four keys
    pass
