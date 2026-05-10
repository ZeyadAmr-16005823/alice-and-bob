# =============================================================================
# main.py
# Author  : Marawan Elgendy
# Purpose : Entry point — runs the full Alice-Bob secure protocol end-to-end
# =============================================================================

import os
from src.rsa_encrypt   import generate_rsa_keypair, sign
from src.rsa_decrypt   import verify, aes_decrypt
from src.diffie_hellman import (generate_dh_private_key, generate_dh_public_key,
                                 compute_shared_secret, derive_session_key, aes_encrypt)
from src.key_manager   import setup_keys

OUTPUT_DIR = "output"
TRANSACTIONS_FILE = os.path.join(OUTPUT_DIR, "transactions.txt")
ENCRYPTED_FILE    = os.path.join(OUTPUT_DIR, "transactions.enc")
DECRYPTED_FILE    = os.path.join(OUTPUT_DIR, "transactions.dec")


def main():
    print("=" * 60)
    print("       Alice & Bob — Secure Transmission Protocol")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Step 0: Setup — generate RSA key pairs for Alice and Bob
    # ------------------------------------------------------------------
    print("\n[0] Generating RSA key pairs...")
    alice_private, alice_public, bob_private, bob_public = setup_keys(generate_rsa_keypair)
    print("    ✔ Alice's key pair generated")
    print("    ✔ Bob's key pair generated")

    # ------------------------------------------------------------------
    # Step 1 & 2: Diffie-Hellman — both parties generate DH values
    # ------------------------------------------------------------------
    print("\n[1] Performing Diffie-Hellman key exchange...")
    alice_dh_private = generate_dh_private_key()
    alice_dh_public  = generate_dh_public_key(alice_dh_private)

    bob_dh_private   = generate_dh_private_key()
    bob_dh_public    = generate_dh_public_key(bob_dh_private)
    print("    ✔ DH public values computed")

    # ------------------------------------------------------------------
    # Step 2: Bob signs his DH public value
    # ------------------------------------------------------------------
    print("\n[2] Bob signing his DH public value...")
    bob_dh_public_bytes = bob_dh_public.to_bytes((bob_dh_public.bit_length() + 7) // 8, 'big')
    bob_signature = sign(bob_private, bob_dh_public_bytes)
    print("    ✔ Bob's signature created")

    # ------------------------------------------------------------------
    # Step 3: Alice verifies Bob's signature
    # ------------------------------------------------------------------
    print("\n[3] Alice verifying Bob's signature...")
    if not verify(bob_public, bob_dh_public_bytes, bob_signature):
        print("    ✘ Bob's signature verification FAILED — aborting")
        return
    print("    ✔ Bob's signature verified")

    # ------------------------------------------------------------------
    # Step 4: Alice signs her DH public value
    # ------------------------------------------------------------------
    print("\n[4] Alice signing her DH public value...")
    alice_dh_public_bytes = alice_dh_public.to_bytes((alice_dh_public.bit_length() + 7) // 8, 'big')
    alice_signature = sign(alice_private, alice_dh_public_bytes)
    print("    ✔ Alice's signature created")

    # ------------------------------------------------------------------
    # Step 5: Bob verifies Alice's signature
    # ------------------------------------------------------------------
    print("\n[5] Bob verifying Alice's signature...")
    if not verify(alice_public, alice_dh_public_bytes, alice_signature):
        print("    ✘ Alice's signature verification FAILED — aborting")
        return
    print("    ✔ Alice's signature verified")

    # ------------------------------------------------------------------
    # Step 6: Both derive the shared session key
    # ------------------------------------------------------------------
    print("\n[6] Deriving shared session key...")
    alice_shared = compute_shared_secret(bob_dh_public, alice_dh_private)
    bob_shared   = compute_shared_secret(alice_dh_public, bob_dh_private)
    assert alice_shared == bob_shared, "Shared secrets do not match!"

    session_key = derive_session_key(alice_shared)
    print("    ✔ Session key derived successfully")

    # ------------------------------------------------------------------
    # Step 7: Alice encrypts the transactions file and signs the ciphertext
    # ------------------------------------------------------------------
    print("\n[7] Alice encrypting and signing the transactions file...")
    with open(TRANSACTIONS_FILE, "rb") as f:
        plaintext = f.read()

    ciphertext, nonce, tag = aes_encrypt(session_key, plaintext)
    ciphertext_signature = sign(alice_private, ciphertext)

    with open(ENCRYPTED_FILE, "wb") as f:
        f.write(ciphertext)
    print(f"    ✔ Encrypted file saved → {ENCRYPTED_FILE}")

    # ------------------------------------------------------------------
    # Step 8: Bob verifies the signature and decrypts the file
    # ------------------------------------------------------------------
    print("\n[8] Bob verifying and decrypting the file...")
    if not verify(alice_public, ciphertext, ciphertext_signature):
        print("    ✘ File signature verification FAILED — aborting")
        return
    print("    ✔ File signature verified")

    decrypted = aes_decrypt(session_key, ciphertext, nonce, tag)

    with open(DECRYPTED_FILE, "wb") as f:
        f.write(decrypted)
    print(f"    ✔ Decrypted file saved → {DECRYPTED_FILE}")

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("   Protocol complete — secure transmission successful ✔")
    print("=" * 60)


if __name__ == "__main__":
    main()
