#!/usr/bin/env python3
"""
Fixed Bitcoin Wallet Decryption
Uses the correct WIF generation and fixes the decryption process
"""

import base58
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def sha256(data):
    return hashlib.sha256(data).digest()

def double_sha256(data):
    return sha256(sha256(data))

def base58check_encode(payload):
    checksum = double_sha256(payload)[:4]
    return base58.b58encode(payload + checksum).decode('utf-8')

def decrypt_with_correct_iv():
    """Decrypt using the exact method from instructions"""
    print("🔧 Fixed Decryption Test")
    print("=" * 50)

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

    # Generate IV using crackBTC method (first 32 hex of double SHA256)
    iv_full = double_sha256(pubkey.encode()).hex()
    iv = iv_full[:32]  # First 32 hex characters = 16 bytes
    print(f"IV full hash: {iv_full}")
    print(f"IV (first 32 hex): {iv}")

    try:
        # Convert to bytes
        encrypted_bytes = bytes.fromhex(encrypted_privkey)
        master_bytes = bytes.fromhex(master_key)
        iv_bytes = bytes.fromhex(iv)

        print(f"Encrypted length: {len(encrypted_bytes)} bytes")
        print(f"Master length: {len(master_bytes)} bytes")
        print(f"IV length: {len(iv_bytes)} bytes")

        # Decrypt
        cipher = Cipher(algorithms.AES(master_bytes), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()

        print(f"Decrypted (with padding): {decrypted_padded.hex()}")

        # Try to extract the private key
        # The decrypted data might have padding or be in different format

        # Method 1: Try standard PKCS#7 padding removal
        if len(decrypted_padded) > 0:
            padding_len = decrypted_padded[-1]
            if 1 <= padding_len <= 16:
                # Validate padding
                padding_bytes = decrypted_padded[-padding_len:]
                if all(b == padding_len for b in padding_bytes):
                    decrypted = decrypted_padded[:-padding_len]
                    print(f"Decrypted (PKCS#7): {decrypted.hex()}")

                    if decrypted.hex() == expected_private:
                        print("✅ SUCCESS: PKCS#7 padding works!")

                        # Generate correct WIF
                        extended = b'\x80' + decrypted  # No compression flag for uncompressed
                        wif = base58check_encode(extended)
                        print(f"Generated WIF: {wif}")

                        if wif == "5JHsqscg3o1iAWjRP83nWWJFbgMrjnXwVQoxejtAqp4t6cCVgbo":
                            print("🎉 PERFECT: WIF matches expected!")
                            return decrypted.hex(), wif
                        else:
                            print(f"❌ WIF mismatch: {wif}")
                    else:
                        print("❌ PKCS#7 result doesn't match expected")
                else:
                    print("❌ Invalid PKCS#7 padding")
            else:
                print(f"Invalid padding length: {padding_len}")

        # Method 2: Try without padding (raw private key)
        if decrypted_padded.hex() == expected_private:
            print("✅ SUCCESS: No padding needed!")
            extended = b'\x80' + decrypted_padded
            wif = base58check_encode(extended)
            print(f"Generated WIF: {wif}")
            return decrypted_padded.hex(), wif

        # Method 3: Try to extract 32-byte private key from decrypted data
        if len(decrypted_padded) >= 32:
            # Try different offsets
            for offset in range(min(16, len(decrypted_padded) - 32 + 1)):
                candidate = decrypted_padded[offset:offset+32]
                if candidate.hex() == expected_private:
                    print(f"✅ SUCCESS: Found private key at offset {offset}!")
                    extended = b'\x80' + candidate
                    wif = base58check_encode(extended)
                    print(f"Generated WIF: {wif}")
                    return candidate.hex(), wif

        print("❌ No decryption method worked")
        return None, None

    except Exception as e:
        print(f"❌ Decryption error: {e}")
        import traceback
        traceback.print_exc()
        return None, None

def test_with_correct_wif():
    """Test with the correct WIF generation"""
    print("\n" + "=" * 50)
    print("🧪 Testing with Correct WIF Generation")
    print("-" * 40)

    expected_private = "3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b7"

    # Generate WIF using the correct method (uncompressed)
    private_bytes = bytes.fromhex(expected_private)
    extended = b'\x80' + private_bytes  # No compression flag
    correct_wif = base58check_encode(extended)

    print(f"Expected private key: {expected_private}")
    print(f"Correct WIF: {correct_wif}")

    # Verify this WIF decodes back correctly
    decoded = base58.b58decode(correct_wif)
    decoded_private = decoded[1:-4].hex()
    print(f"Decoded private key: {decoded_private}")

    if decoded_private == expected_private:
        print("✅ WIF generation and decoding works perfectly!")
        return correct_wif
    else:
        print("❌ WIF round-trip failed")
        return None

def main():
    print("🔧 Fixed Bitcoin Wallet Decryption Test")
    print("=" * 50)

    # Test WIF generation
    correct_wif = test_with_correct_wif()

    # Test decryption
    decrypted, wif = decrypt_with_correct_iv()

    if decrypted and wif == correct_wif:
        print("\n🎉 SUCCESS! Decryption is working correctly!")
        print(f"✅ Decrypted private key: {decrypted}")
        print(f"✅ Generated WIF: {wif}")
        print(f"✅ Matches expected: {correct_wif}")

        print("\n🔍 ONLINE VERIFICATION:")
        print(f"   Go to: https://iancoleman.io/bitcoin-key-compression/")
        print(f"   Enter WIF: {wif}")
        print(f"   Should show address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    else:
        print("\n❌ Still having issues with decryption")

if __name__ == "__main__":
    main()
