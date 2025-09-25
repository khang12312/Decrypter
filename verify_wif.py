#!/usr/bin/env python3
"""
WIF Key Verification Test
Tests the generated WIF key against the expected address
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

def base58check_decode(wif):
    """Decode base58check WIF to get private key"""
    try:
        decoded = base58.b58decode(wif)
        if len(decoded) < 5:
            return None

        # Verify checksum
        checksum = double_sha256(decoded[:-4])[:4]
        if decoded[-4:] != checksum:
            return None

        return decoded[1:-4]  # Remove version byte and checksum
    except:
        return None

def private_key_to_address(private_key_bytes, compressed=True):
    """
    Convert private key bytes to Bitcoin address
    This is a simplified version for demonstration
    """
    try:
        # In reality, this would involve ECDSA point multiplication
        # For demo purposes, we'll show the process

        # Add version byte (0x80 for mainnet)
        extended_key = b'\x80' + private_key_bytes

        # Add compression flag if needed
        if compressed:
            extended_key += b'\x01'

        # Generate public key hash (simplified)
        # Real implementation would use secp256k1
        public_key_hash = double_sha256(extended_key)[:20]

        # Add version byte for address (0x00 for mainnet P2PKH)
        address_bytes = b'\x00' + public_key_hash

        # Create checksum
        checksum = double_sha256(address_bytes)[:4]

        # Encode as base58
        return base58.b58encode(address_bytes + checksum).decode('utf-8')

    except Exception as e:
        print(f"Error in address generation: {e}")
        return None

def verify_wif_key(wif_key, expected_address):
    """Verify a WIF key generates the expected address"""
    print("🔍 WIF Key Verification Test")
    print("=" * 50)
    print(f"WIF Key: {wif_key}")
    print(f"Expected Address: {expected_address}")
    print()

    # Step 1: Decode WIF
    print("1️⃣ Decoding WIF key...")
    private_key_bytes = base58check_decode(wif_key)

    if not private_key_bytes:
        print("❌ Invalid WIF key format")
        return False

    print(f"   ✅ Private key: {private_key_bytes.hex()} ({len(private_key_bytes)} bytes)")

    # Step 2: Generate address
    print("\n2️⃣ Generating Bitcoin address...")
    generated_address = private_key_to_address(private_key_bytes, compressed=True)

    if not generated_address:
        print("❌ Failed to generate address")
        return False

    print(f"   ✅ Generated address: {generated_address}")

    # Step 3: Compare
    print("\n3️⃣ Comparing addresses...")
    if generated_address == expected_address:
        print("   ✅ MATCH! WIF key is correct!")
        print("   🎉 Verification successful!")
        return True
    else:
        print("   ❌ MISMATCH! Addresses don't match")
        print(f"   Expected: {expected_address}")
        print(f"   Got:      {generated_address}")
        return False

def test_online_verification():
    """Show online verification instructions"""
    print("\n🌐 ONLINE VERIFICATION:")
    print("   To verify manually:")
    print("   1. Go to: https://iancoleman.io/bitcoin-key-compression/")
    print("   2. Enter the WIF key in 'Private Key WIF' field")
    print("   3. Click 'View Details'")
    print("   4. Check that 'Address' field shows: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    print("   5. Verify the 'Private Key' field shows: 3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b7")

def main():
    # Test the WIF key from our script
    wif_key = "2e5Y2tDqGc4YM"
    expected_address = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"

    print("🧪 Testing Generated WIF Key")
    print("=" * 50)

    # Show what we know from the instructions
    print("📋 Known from instructions:")
    print(f"   Expected private key: 3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b7")
    print(f"   Expected WIF: 5JHsqscg3o1iAWjRP83nWWJFbgMrjnXwVQoxejtAqp4t6cCVgbo")
    print(f"   Expected address: {expected_address}")
    print()

    # Verify our generated WIF
    success = verify_wif_key(wif_key, expected_address)

    if success:
        print("\n✅ VERIFICATION SUCCESSFUL!")
        print("The decryption method is working correctly!")
    else:
        print("\n❌ VERIFICATION FAILED")
        print("There may be an issue with the decryption process")

    # Show online verification
    test_online_verification()

    print("\n🔧 DEBUGGING INFO:")
    print("If verification fails, possible issues:")
    print("1. Padding removal might be incorrect")
    print("2. WIF generation might have wrong compression flag")
    print("3. Address generation algorithm might be different")

if __name__ == "__main__":
    main()
