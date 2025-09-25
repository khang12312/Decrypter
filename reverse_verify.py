#!/usr/bin/env python3
"""
Reverse WIF Verification Test
Tests by starting with the expected private key and working forward
"""

import base58
import hashlib
import binascii

def sha256(data):
    """SHA256 hash function"""
    return hashlib.sha256(data).digest()

def double_sha256(data):
    """Double SHA256 hash"""
    return sha256(sha256(data))

def base58check_encode(payload):
    """Base58Check encode"""
    checksum = double_sha256(payload)[:4]
    return base58.b58encode(payload + checksum).decode('utf-8')

def private_key_to_wif(private_key_hex, compressed=True):
    """Convert hex private key to WIF format"""
    private_key_bytes = bytes.fromhex(private_key_hex)

    # Add version byte (0x80 for mainnet)
    extended_key = b'\x80' + private_key_bytes

    # Add compression flag if needed
    if compressed:
        extended_key += b'\x01'

    return base58check_encode(extended_key)

def test_reverse_verification():
    """Test by starting with expected private key and generating WIF"""
    print("🔄 Reverse WIF Verification Test")
    print("=" * 50)

    # Known correct values from instructions
    expected_private_key = "3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b7"
    expected_wif = "5JHsqscg3o1iAWjRP83nWWJFbgMrjnXwVQoxejtAqp4t6cCVgbo"
    expected_address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

    print("📋 Expected values from instructions:")
    print(f"   Private Key: {expected_private_key}")
    print(f"   WIF: {expected_wif}")
    print(f"   Address: {expected_address}")
    print()

    # Test 1: Generate WIF from expected private key
    print("1️⃣ Generating WIF from expected private key...")
    generated_wif_compressed = private_key_to_wif(expected_private_key, compressed=True)
    generated_wif_uncompressed = private_key_to_wif(expected_private_key, compressed=False)

    print(f"   Generated WIF (compressed): {generated_wif_compressed}")
    print(f"   Generated WIF (uncompressed): {generated_wif_uncompressed}")

    if generated_wif_compressed == expected_wif:
        print("   ✅ WIF generation is CORRECT!")
    else:
        print("   ❌ WIF generation is INCORRECT!")
        return False

    # Test 2: Test our decryption result
    print("\n2️⃣ Testing our decryption result...")
    our_wif = "2e5Y2tDqGc4YM"

    # Decode our WIF to get private key
    try:
        decoded = base58.b58decode(our_wif)
        if len(decoded) >= 5:
            checksum = double_sha256(decoded[:-4])[:4]
            if decoded[-4:] == checksum:
                our_private_key = decoded[1:-4].hex()  # Remove version and checksum
                print(f"   Our generated private key: {our_private_key}")

                # Compare with expected
                if our_private_key == expected_private_key:
                    print("   ✅ Our decryption produced the CORRECT private key!")
                    return True
                else:
                    print("   ❌ Our decryption produced the WRONG private key!")
                    print(f"   Expected: {expected_private_key}")
                    print(f"   Got:      {our_private_key}")
                    return False
    except Exception as e:
        print(f"   ❌ Error decoding our WIF: {e}")
        return False

def test_padding_issue():
    """Test different padding scenarios"""
    print("\n🔧 Testing padding scenarios...")

    encrypted_key = "2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155"
    master_key = "0399571599931743677e2264a2523c2c031ce23c213ee9bc6342ed62ec6ed613"

    # Generate IV correctly
    iv_full_hash = double_sha256(encrypted_key.encode()).hex()
    iv = iv_full_hash[:32]

    print(f"   IV: {iv}")

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        encrypted_bytes = bytes.fromhex(encrypted_key)
        master_bytes = bytes.fromhex(master_key)
        iv_bytes = bytes.fromhex(iv)

        cipher = Cipher(algorithms.AES(master_bytes), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()

        print(f"   Decrypted (with padding): {decrypted_padded.hex()}")

        # Try different padding scenarios
        expected_private = "3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b7"

        # Scenario 1: No padding
        if decrypted_padded.hex() == expected_private:
            print("   ✅ No padding needed - matches expected!")
            return True

        # Scenario 2: Remove padding
        padding_length = decrypted_padded[-1]
        if padding_length > 0 and padding_length <= 16:
            decrypted = decrypted_padded[:-padding_length]
            print(f"   Decrypted (no padding): {decrypted.hex()}")

            if decrypted.hex() == expected_private:
                print("   ✅ Padding removal works correctly!")
                return True

        print("   ❌ No padding scenario worked")
        return False

    except Exception as e:
        print(f"   ❌ Decryption error: {e}")
        return False

def main():
    print("🧪 Testing WIF Key Verification")
    print("=" * 50)

    # Test reverse verification
    success1 = test_reverse_verification()

    # Test padding scenarios
    success2 = test_padding_issue()

    if success1 and success2:
        print("\n✅ ALL TESTS PASSED!")
        print("The decryption method is working correctly!")
    else:
        print("\n❌ SOME TESTS FAILED")
        print("There are still issues with the decryption process")

    print("\n🔍 MANUAL VERIFICATION:")
    print("   Go to: https://iancoleman.io/bitcoin-key-compression/")
    print("   Enter WIF: 5JHsqscg3o1iAWjRP83nWWJFbgMrjnXwVQoxejtAqp4t6cCVgbo")
    print("   Should show address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")

if __name__ == "__main__":
    main()
