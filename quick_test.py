#!/usr/bin/env python3
"""
Quick Bitcoin Ckey Finder - Simplified version for testing
"""

import sys
import os
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base58
import hashlib

def sha256(data):
    return hashlib.sha256(data).digest()

def double_sha256(data):
    return sha256(sha256(data))

def base58check_encode(payload):
    checksum = double_sha256(payload)[:4]
    return base58.b58encode(payload + checksum).decode('utf-8')

def find_valid_ckeys(wallet_file):
    """Find valid ckeys in wallet file"""
    print("🔍 Searching for valid ckeys...")

    try:
        with open(wallet_file, 'rb') as f:
            data = f.read()

        print(f"📁 Read {len(data)} bytes from wallet file")

        # Look for the exact pattern from the instructions
        # This is a more targeted search
        ckeys_found = []

        # Look for known ckey pattern: 0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f52e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155
        # Split into pubkey + encrypted key
        target_pubkey = "0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5"
        target_encrypted = "2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155"

        # Search for this exact pattern
        data_str = data.decode('latin-1', errors='ignore')
        if target_pubkey in data_str and target_encrypted in data_str:
            ckeys_found.append({
                'pubkey': target_pubkey,
                'encrypted_privkey': target_encrypted
            })
            print(f"✅ Found target ckey!")

        # Also search for any ckey patterns in the file
        pattern = r'ckey\s+([0-9a-fA-F]{66})\s*([0-9a-fA-F]{64})'
        matches = re.findall(pattern, data_str, re.IGNORECASE | re.MULTILINE)

        for pubkey, encrypted_privkey in matches:
            if len(pubkey) == 66 and len(encrypted_privkey) == 64:
                if pubkey.startswith(('02', '03')):
                    ckeys_found.append({
                        'pubkey': pubkey,
                        'encrypted_privkey': encrypted_privkey
                    })

        return ckeys_found

    except Exception as e:
        print(f"❌ Error: {e}")
        return []

def test_decryption():
    """Test decryption with the exact example from instructions"""
    print("\n🧪 Testing decryption with exact example from instructions...")

    master_key = bytes.fromhex("0399571599931743677e2264a2523c2c031ce23c213ee9bc6342ed62ec6ed613")

    # Example from instructions
    pubkey = "0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5"
    encrypted_privkey = "2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155"

    # Generate IV - CORRECTED METHOD from instructions
    # The IV is the FIRST 32 HEX CHARS of double SHA256 (not first 32 bytes)
    iv_input = pubkey.encode()
    iv_full_hash = double_sha256(iv_input).hex()
    iv = iv_full_hash[:32]  # First 32 hex characters = 16 bytes

    print(f"Pubkey: {pubkey}")
    print(f"IV Full Hash: {iv_full_hash}")
    print(f"IV (first 32 hex): {iv}")
    print(f"Master Key: {master_key.hex()}")

    try:
        # Decrypt
        encrypted_key = bytes.fromhex(encrypted_privkey)
        iv_bytes = bytes.fromhex(iv)

        print(f"Encrypted key length: {len(encrypted_key)} bytes")
        print(f"IV length: {len(iv_bytes)} bytes")

        cipher = Cipher(algorithms.AES(master_key), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(encrypted_key) + decryptor.finalize()

        # Remove padding
        padding_length = decrypted_padded[-1]
        decrypted = decrypted_padded[:-padding_length]

        print(f"✅ Decrypted: {decrypted.hex()}")

        # Convert to WIF
        extended_key = b'\x80' + decrypted
        checksum = double_sha256(extended_key)[:4]
        wif = base58check_encode(extended_key + checksum)

        print(f"✅ WIF: {wif}")

        return decrypted.hex(), wif

    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        import traceback
        traceback.print_exc()
        return None, None

def main():
    if len(sys.argv) != 2:
        print("Usage: python quick_test.py <wallet_file>")
        sys.exit(1)

    wallet_file = sys.argv[1]

    if not os.path.exists(wallet_file):
        print(f"❌ Wallet file not found: {wallet_file}")
        sys.exit(1)

    print("🚀 Quick Bitcoin Ckey Test")
    print("=" * 40)

    # Find ckeys
    ckeys = find_valid_ckeys(wallet_file)

    if ckeys:
        print(f"\n✅ Found {len(ckeys)} ckeys!")

        for i, ckey in enumerate(ckeys, 1):
            print(f"\n🔐 Ckey {i}:")
            print(f"   Pubkey: {ckey['pubkey']}")
            print(f"   Encrypted: {ckey['encrypted_privkey']}")

        # Test decryption
        decrypted, wif = test_decryption()

        if decrypted and wif:
            print("🎯 VERIFICATION:")
            print(f"   Decrypted Private Key: {decrypted}")
            print(f"   WIF Key: {wif}")
            print("   ")
            print("   ✅ Go to: https://iancoleman.io/bitcoin-key-compression/")
            print(f"   ✅ Enter WIF: {wif}")
            print("   ✅ Should match address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    else:
        print("❌ No ckeys found")
        print("\n💡 This could mean:")
        print("   1. Different wallet format")
        print("   2. File is encrypted/corrupted")
        print("   3. Ckeys are in different location")

        # Still try the exact example
        print("\n🔧 Trying exact example from instructions...")
        decrypted, wif = test_decryption()

if __name__ == "__main__":
    main()
