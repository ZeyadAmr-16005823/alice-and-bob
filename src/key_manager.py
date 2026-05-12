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
    os.makedirs(KEYS_DIR, exist_ok=True)
    path = os.path.join(KEYS_DIR, filename)
    with open(path, "wb") as f:
        f.write(private_key.export_key("PEM"))


def save_public_key(public_key, filename: str):
    """
    Serialize and save an RSA public key to a .pem file.

    Args:
        public_key : RsaKey — the RSA public key to save
        filename   : str    — output filename (e.g. 'alice_public.pem')
    """
    os.makedirs(KEYS_DIR, exist_ok=True)
    path = os.path.join(KEYS_DIR, filename)
    with open(path, "wb") as f:
        f.write(public_key.export_key("PEM"))


def load_private_key(filename: str):
    """
    Load an RSA private key from a .pem file.

    Args:
        filename : str — the .pem file to load (from keys/ directory)

    Returns:
        RsaKey object
    """
    path = os.path.join(KEYS_DIR, filename)
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_public_key(filename: str):
    """
    Load an RSA public key from a .pem file.

    Args:
        filename : str — the .pem file to load (from keys/ directory)

    Returns:
        RsaKey object
    """
    path = os.path.join(KEYS_DIR, filename)
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def setup_keys(generate_keypair_fn):
    """
    Generate and save RSA key pairs for both Alice and Bob.

    Args:
        generate_keypair_fn : callable — the generate_rsa_keypair function from rsa_encrypt.py

    Returns:
        (alice_private, alice_public, bob_private, bob_public)
    """
    os.makedirs(KEYS_DIR, exist_ok=True)

    alice_private, alice_public = generate_keypair_fn()
    bob_private,   bob_public   = generate_keypair_fn()

    save_private_key(alice_private, "alice_private.pem")
    save_public_key (alice_public,  "alice_public.pem")
    save_private_key(bob_private,   "bob_private.pem")
    save_public_key (bob_public,    "bob_public.pem")

    return alice_private, alice_public, bob_private, bob_public