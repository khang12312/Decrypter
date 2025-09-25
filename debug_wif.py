#!/usr/bin/env python3
"""
Debug WIF Generation
Analyzes the correct WIF generation process
"""

import base58
import hashlib

def sha256(data):
    return hashlib.sha256(data).digest()

def double_sha256(data):
    return sha256(sha256(data))

def base58check_encode(payload):
    checksum = double_sha256(payload)[:4]
    return base58.b58encode(payload + checksum).decode('utf-8')

def analyze_expected_wif():
    """Analyze the expected WIF from instructions"""
    print("🔍 Analyzing Expected WIF")
    print("=" * 50)

    # Expected WIF from instructions
    expected_wif = "5JHsqscg3o1iAWjRP83nWWJFbgMrjnXwVQoxejtAqp4t6cCVgbo"
    expected_private = "3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b7"

    print(f"Expected WIF: {expected_wif}")
    print(f"Expected Private Key: {expected_private}")
    print()

    # Decode the expected WIF
    try:
        decoded = base58.b58decode(expected_wif)
        print(f"Decoded WIF: {decoded.hex()}")

        # Verify checksum
        checksum = double_sha256(decoded[:-4])[:4]
        if decoded[-4:] == checksum:
            print("✅ Checksum is valid")

            # Extract private key
            version = decoded[0]
            private_key = decoded[1:-4]
            compression_flag = decoded[-5] if len(decoded) > 37 else None

            print(f"Version byte: 0x{version:02x}")
            print(f"Private key: {private_key.hex()}")
            print(f"Compression flag: {compression_flag}")

            if compression_flag == 1:
                print("📌 This is a COMPRESSED private key")
            else:
                print("📌 This is an UNCOMPRESSED private key")

        else:
            print("❌ Checksum is invalid")

    except Exception as e:
        print(f"❌ Error decoding WIF: {e}")

    print("\n" + "=" * 50)

    # Test WIF generation with different methods
    print("🧪 Testing WIF Generation Methods")
    print("-" * 40)

    private_bytes = bytes.fromhex(expected_private)

    # Method 1: Uncompressed (no compression flag)
    extended_uncompressed = b'\x80' + private_bytes
    wif_uncompressed = base58check_encode(extended_uncompressed)
    print(f"Uncompressed WIF: {wif_uncompressed}")

    # Method 2: Compressed (with compression flag)
    extended_compressed = b'\x80' + private_bytes + b'\x01'
    wif_compressed = base58check_encode(extended_compressed)
    print(f"Compressed WIF: {wif_compressed}")

    # Method 3: Try different version bytes
    for version in [0x80, 0xEF]:  # Mainnet, Testnet
        for compressed in [False, True]:
            flag = b'\x01' if compressed else b''
            extended = bytes([version]) + private_bytes + flag
            wif = base58check_encode(extended)
            print(f"Version 0x{version:02x}, Compressed={compressed}: {wif}")

    print(f"\n🎯 Target WIF: {expected_wif}")

def test_correct_decryption():
    """Test the correct decryption process step by step"""
    print("\n" + "=" * 50)
    print("🔧 Testing Correct Decryption Process")
    print("-" * 40)

    # Exact values from instructions
    pubkey = "0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5"
    encrypted_privkey = "2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155"
    master_key = "0399571599931743677e2264a2523c2c031ce23c213ee9bc6342ed62ec6ed613"
    expected_private = "3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b7"

    print("Input values:")
    print(f"  Pubkey: {pubkey}")
    print(f"  Encrypted: {encrypted_privkey}")
    print(f"  Master: {master_key}")
    print(f"  Expected: {expected_private}")
    print()

    # Correct IV generation
    iv_full = double_sha256(pubkey.encode()).hex()
    iv = iv_full[:32]  # First 32 hex chars
    print(f"IV full hash: {iv_full}")
    print(f"IV (first 32 hex): {iv}")

    # Decrypt
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        encrypted_bytes = bytes.fromhex(encrypted_privkey)
        master_bytes = bytes.fromhex(master_key)
        iv_bytes = bytes.fromhex(iv)

        cipher = Cipher(algorithms.AES(master_bytes), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()

        print(f"Decrypted (padded): {decrypted_padded.hex()}")

        # Try padding removal
        if len(decrypted_padded) > 0:
            padding_len = decrypted_padded[-1]
            if padding_len > 0 and padding_len <= 16:
                decrypted = decrypted_padded[:-padding_len]
                print(f"Decrypted (no padding): {decrypted.hex()}")

                if decrypted.hex() == expected_private:
                    print("✅ SUCCESS: Decryption works correctly!")

                    # Generate WIF
                    extended = b'\x80' + decrypted
                    wif = base58check_encode(extended)
                    print(f"Generated WIF: {wif}")

                    if wif == "5JHsqscg3o1iAWjRP83nWWJFbgMrjnXwVQoxejtAqp4t6cCVgbo":
                        print("🎉 PERFECT: WIF matches expected!")
                    else:
                        print(f"❌ WIF mismatch: expected 5JH..., got {wif}")
                else:
                    print("❌ Decryption result doesn't match expected")
            else:
                print(f"Invalid padding length: {padding_len}")

    except Exception as e:
        print(f"❌ Decryption error: {e}")
        import traceback
        traceback.print_exc()

def main():
    analyze_expected_wif()
    test_correct_decryption()

if __name__ == "__main__":
    main()
