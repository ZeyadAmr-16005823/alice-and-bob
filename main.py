# =============================================================================
# main.py
# Author  : Marawan Elgendy
# Purpose : Entry point - runs the full Alice-Bob secure protocol end-to-end
# =============================================================================

import os
from src.rsa_encrypt    import generate_rsa_keypair, sign
from src.rsa_decrypt    import verify, aes_decrypt
from src.diffie_hellman import (generate_dh_private_key, generate_dh_public_key,
                                 compute_shared_secret, derive_session_key, aes_encrypt)
from src.key_manager    import setup_keys

OUTPUT_DIR = "output"


def get_input_file() -> str:
    """Prompt the user for the input transactions file path."""
    default = os.path.join(OUTPUT_DIR, "transactions.txt")
    path = input(f"\nEnter input file path (default: {default}): ").strip()
    if not path:
        path = default
    if not os.path.exists(path):
        print(f"[FAIL] File not found: {path}")
        exit(1)
    return path


def get_output_files(input_path: str):
    """Derive encrypted and decrypted output file paths from the input file name."""
    base      = os.path.splitext(os.path.basename(input_path))[0]
    enc_file  = os.path.join(OUTPUT_DIR, base + ".enc")
    dec_file  = os.path.join(OUTPUT_DIR, base + ".dec")
    return enc_file, dec_file


def hex_preview(data: bytes, length: int = 32) -> str:
    """Return a short hex preview of bytes."""
    return data.hex()[:length] + "..."


def main():
    print("=" * 60)
    print("       Alice & Bob - Secure Transmission Protocol")
    print("=" * 60)

    # ------------------------------------------------------------------
    # File input / output
    # ------------------------------------------------------------------
    input_file              = get_input_file()
    encrypted_file, decrypted_file = get_output_files(input_file)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"\n  Input file    : {input_file}")
    print(f"  Encrypted file: {encrypted_file}")
    print(f"  Decrypted file: {decrypted_file}")

    # ------------------------------------------------------------------
    # Step 0: Generate RSA key pairs for Alice and Bob
    # ------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[0] Generating RSA key pairs...")
    alice_private, alice_public, bob_private, bob_public = setup_keys(generate_rsa_keypair)

    print(f"\n  Alice's Public Key (n): {hex_preview(alice_public.n.to_bytes(256, 'big'))}")
    print(f"  Bob's   Public Key (n): {hex_preview(bob_public.n.to_bytes(256, 'big'))}")
    print("\n  [OK] RSA key pairs generated and saved to keys/")

    # ------------------------------------------------------------------
    # Step 1: Both parties generate DH public/private values
    # ------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[1] Performing Diffie-Hellman key exchange...")

    alice_dh_private = generate_dh_private_key()
    alice_dh_public  = generate_dh_public_key(alice_dh_private)

    bob_dh_private   = generate_dh_private_key()
    bob_dh_public    = generate_dh_public_key(bob_dh_private)

    alice_dh_pub_bytes = alice_dh_public.to_bytes((alice_dh_public.bit_length() + 7) // 8, 'big')
    bob_dh_pub_bytes   = bob_dh_public.to_bytes((bob_dh_public.bit_length() + 7) // 8, 'big')

    print(f"\n  Alice's DH Public Value : {hex_preview(alice_dh_pub_bytes)}")
    print(f"  Bob's   DH Public Value : {hex_preview(bob_dh_pub_bytes)}")
    print("\n  [OK] DH public values computed")

    # ------------------------------------------------------------------
    # Step 2: Bob signs his DH public value
    # ------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[2] Bob signing his DH public value...")

    bob_dh_signature = sign(bob_private, bob_dh_pub_bytes)

    print(f"\n  Bob's DH Signature : {hex_preview(bob_dh_signature)}")
    print("\n  [OK] Bob's signature created")

    # ------------------------------------------------------------------
    # Step 3: Alice verifies Bob's signature
    # ------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[3] Alice verifying Bob's signature...")

    if not verify(bob_public, bob_dh_pub_bytes, bob_dh_signature):
        print("\n  [FAIL] Bob's signature verification FAILED - aborting")
        return
    print("\n  [OK] Bob's signature verified")

    # ------------------------------------------------------------------
    # Step 4: Alice signs her DH public value
    # ------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[4] Alice signing her DH public value...")

    alice_dh_signature = sign(alice_private, alice_dh_pub_bytes)

    print(f"\n  Alice's DH Signature : {hex_preview(alice_dh_signature)}")
    print("\n  [OK] Alice's signature created")

    # ------------------------------------------------------------------
    # Step 5: Bob verifies Alice's signature
    # ------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[5] Bob verifying Alice's signature...")

    if not verify(alice_public, alice_dh_pub_bytes, alice_dh_signature):
        print("\n  [FAIL] Alice's signature verification FAILED - aborting")
        return
    print("\n  [OK] Alice's signature verified")

    # ------------------------------------------------------------------
    # Step 6: Both derive the shared session key
    # ------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[6] Deriving shared session key...")

    alice_shared = compute_shared_secret(bob_dh_public,   alice_dh_private)
    bob_shared   = compute_shared_secret(alice_dh_public, bob_dh_private)
    assert alice_shared == bob_shared, "Shared secrets do not match!"

    session_key = derive_session_key(alice_shared)

    shared_bytes = alice_shared.to_bytes((alice_shared.bit_length() + 7) // 8, 'big')
    print(f"\n  DH Shared Secret : {hex_preview(shared_bytes)}")
    print(f"  Session Key (AES): {session_key.hex()}")
    print("\n  [OK] Session key derived successfully")

    # ------------------------------------------------------------------
    # Step 7: Alice encrypts the file and signs the ciphertext
    # ------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[7] Alice encrypting and signing the transactions file...")

    with open(input_file, "rb") as f:
        plaintext = f.read()

    ciphertext, nonce, tag   = aes_encrypt(session_key, plaintext)
    ciphertext_signature     = sign(alice_private, ciphertext)

    # Format: [16 bytes nonce][16 bytes tag][rest: ciphertext]
    with open(encrypted_file, "wb") as f:
        f.write(nonce + tag + ciphertext)

    print(f"\n  Nonce      : {nonce.hex()}")
    print(f"  Tag        : {tag.hex()}")
    print(f"  Ciphertext : {hex_preview(ciphertext)}")
    print(f"  Signature  : {hex_preview(ciphertext_signature)}")
    print(f"\n  [OK] Encrypted file saved -> {encrypted_file}")

    # ------------------------------------------------------------------
    # Step 8: Bob verifies the signature and decrypts the file
    # ------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("[8] Bob verifying and decrypting the file...")

    if not verify(alice_public, ciphertext, ciphertext_signature):
        print("\n  [FAIL] File signature verification FAILED - aborting")
        return
    print("\n  [OK] File signature verified")

    decrypted = aes_decrypt(session_key, ciphertext, nonce, tag)

    with open(decrypted_file, "wb") as f:
        f.write(decrypted)

    print(f"\n  Decrypted content preview:")
    print(f"  {decrypted[:200].decode('utf-8', errors='replace')}")
    print(f"\n  [OK] Decrypted file saved -> {decrypted_file}")

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("   Protocol complete - secure transmission successful [OK]")
    print("=" * 60)


if __name__ == "__main__":
    main()