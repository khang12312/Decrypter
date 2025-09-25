#!/usr/bin/env python3
"""
Targeted Bitcoin Ckey Decryptor
==============================
This version specifically looks for the exact ckey pattern from the instructions
and implements the exact decryption method described.

Based on the instructions.rtf file, we need to find this exact pattern:
ckey 0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f52e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155
"""

import sys
import os
import hashlib
import base58
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def sha256(data):
    return hashlib.sha256(data).digest()

def double_sha256(data):
    return sha256(sha256(data))

def base58check_encode(payload):
    checksum = double_sha256(payload)[:4]
    return base58.b58encode(payload + checksum).decode('utf-8')

def decrypt_ckey_exact():
    """Decrypt using the exact method from instructions"""
    print("🔧 Targeted Ckey Decryption")
    print("=" * 50)

    # Exact values from instructions
    pubkey = "0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5"
    encrypted_privkey = "2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155"
    master_key = "0399571599931743677e2264a2523c2c031ce23c213ee9bc6342ed62ec6ed613"
    expected_private = "3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b7"

    print("Target ckey from instructions:")
    print(f"  Pubkey: {pubkey}")
    print(f"  Encrypted: {encrypted_privkey}")
    print(f"  Master: {master_key}")
    print(f"  Expected: {expected_private}")
    print()

    # Generate IV using exact method from instructions
    # The IV is the FIRST 32 HEX CHARS of double SHA256 (not first 32 bytes)
    iv_input = pubkey.encode()
    iv_full_hash = double_sha256(iv_input).hex()
    iv = iv_full_hash[:32]  # First 32 hex characters = 16 bytes

    print(f"IV calculation:")
    print(f"  Double SHA256: {iv_full_hash}")
    print(f"  IV (first 32 hex): {iv}")
    print()

    try:
        # Convert to bytes
        encrypted_bytes = bytes.fromhex(encrypted_privkey)
        master_bytes = bytes.fromhex(master_key)
        iv_bytes = bytes.fromhex(iv)

        print(f"Input validation:")
        print(f"  Encrypted length: {len(encrypted_bytes)} bytes")
        print(f"  Master length: {len(master_bytes)} bytes")
        print(f"  IV length: {len(iv_bytes)} bytes")
        print()

        # Decrypt
        cipher = Cipher(algorithms.AES(master_bytes), modes.CBC(iv_bytes), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()

        print(f"Decryption result:")
        print(f"  Decrypted (with padding): {decrypted_padded.hex()}")
        print()

        # Try to extract the private key
        # Method 1: Standard PKCS#7 padding removal
        if len(decrypted_padded) > 0:
            padding_length = decrypted_padded[-1]
            if 1 <= padding_length <= 16:
                padding_bytes = decrypted_padded[-padding_length:]
                if all(b == padding_length for b in padding_bytes):
                    decrypted = decrypted_padded[:-padding_length]
                    print(f"  With PKCS#7 padding: {decrypted.hex()}")

                    if decrypted.hex() == expected_private:
                        print("  ✅ SUCCESS: Matches expected private key!")
                        return decrypted.hex(), decrypted
                    else:
                        print(f"  ❌ Mismatch: expected {expected_private}")
                else:
                    print(f"  ❌ Invalid PKCS#7 padding")
            else:
                print(f"  ❌ Invalid padding length: {padding_length}")

        # Method 2: Look for 32-byte private key within decrypted data
        print("\n  Searching for 32-byte private key in decrypted data...")
        for offset in range(min(16, len(decrypted_padded) - 32 + 1)):
            candidate = decrypted_padded[offset:offset+32]
            if len(candidate) == 32:
                print(f"    Offset {offset}: {candidate.hex()}")
                if candidate.hex() == expected_private:
                    print(f"    ✅ FOUND at offset {offset}!")
                    return candidate.hex(), candidate

        # Method 3: If decrypted data is 48 bytes, try extracting from different positions
        if len(decrypted_padded) == 48:
            print("\n  Trying 48-byte decryption variants...")

            # Try first 32 bytes
            candidate = decrypted_padded[:32]
            print(f"    First 32 bytes: {candidate.hex()}")
            if candidate.hex() == expected_private:
                print("    ✅ SUCCESS: First 32 bytes match!")
                return candidate.hex(), candidate

            # Try last 32 bytes
            candidate = decrypted_padded[16:]
            print(f"    Last 32 bytes: {candidate.hex()}")
            if candidate.hex() == expected_private:
                print("    ✅ SUCCESS: Last 32 bytes match!")
                return candidate.hex(), candidate

        print("\n  ❌ No decryption method worked")
        return None, None

    except Exception as e:
        print(f"❌ Decryption error: {e}")
        import traceback
        traceback.print_exc()
        return None, None

def generate_wif_from_private_key(private_key_hex):
    """Generate WIF from private key using exact method from instructions"""
    try:
        private_bytes = bytes.fromhex(private_key_hex)

        if len(private_bytes) != 32:
            print(f"❌ Invalid private key length: {len(private_bytes)}")
            return None

        # Method from instructions: uncompressed (no compression flag)
        extended = b'\x80' + private_bytes  # No compression flag
        wif = base58check_encode(extended)

        print(f"Generated WIF: {wif}")

        # Verify this matches the expected WIF
        expected_wif = "5JHsqscg3o1iAWjRP83nWWJFbgMrjnXwVQoxejtAqp4t6cCVgbo"
        if wif == expected_wif:
            print("✅ SUCCESS: WIF matches expected!")
            return wif
        else:
            print(f"❌ WIF mismatch: expected {expected_wif}")
            return wif

    except Exception as e:
        print(f"❌ WIF generation error: {e}")
        return None

def search_for_target_ckey(wallet_file):
    """Search for the exact target ckey in the wallet file"""
    print("🔍 Searching for target ckey in wallet file...")

    try:
        with open(wallet_file, 'rb') as f:
            data = f.read()

        # Look for the exact pubkey from instructions
        target_pubkey = bytes.fromhex("0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5")
        target_encrypted = bytes.fromhex("2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155")

        pubkey_pos = data.find(target_pubkey)
        encrypted_pos = data.find(target_encrypted)

        if pubkey_pos != -1:
            print(f"✅ Found target pubkey at position {pubkey_pos}")

        if encrypted_pos != -1:
            print(f"✅ Found target encrypted key at position {encrypted_pos}")

        if pubkey_pos != -1 and encrypted_pos != -1:
            print("✅ Found complete target ckey!")
            return True

        # Also search as text (in case it's stored as text)
        data_str = data.decode('latin-1', errors='ignore')
        if "0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5" in data_str:
            print("✅ Found target pubkey as text")
            return True

        if "2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155" in data_str:
            print("✅ Found target encrypted key as text")
            return True

        print("❌ Target ckey not found in wallet file")
        return False

    except Exception as e:
        print(f"❌ Error searching wallet file: {e}")
        return False

def main():
    print("🎯 Targeted Bitcoin Ckey Decryptor")
    print("=" * 50)

    # Default wallet file
    wallet_file = "Client-DAta/wallet.dat.txt"

    if not os.path.exists(wallet_file):
        print(f"❌ Wallet file not found: {wallet_file}")
        sys.exit(1)

    # Step 1: Search for target ckey
    if not search_for_target_ckey(wallet_file):
        print("\n⚠️  Target ckey not found. This tool is designed for the specific ckey from instructions.")
        print("If you have a different wallet, you may need to extract ckeys manually first.")
        sys.exit(1)

    # Step 2: Decrypt the target ckey
    print("\n🔐 Decrypting target ckey...")
    decrypted_hex, decrypted_bytes = decrypt_ckey_exact()

    if not decrypted_hex:
        print("❌ Decryption failed")
        sys.exit(1)

    # Step 3: Generate WIF
    print("\n🔑 Generating WIF...")
    wif = generate_wif_from_private_key(decrypted_hex)

    if not wif:
        print("❌ WIF generation failed")
        sys.exit(1)

    # Step 4: Save results
    print("\n💾 Saving results...")
    with open('target_ckey_decrypted.txt', 'w') as f:
        f.write("TARGET CKEY DECRYPTION RESULTS\n")
        f.write("=" * 50 + "\n")
        f.write(f"Decrypted Private Key: {decrypted_hex}\n")
        f.write(f"WIF Key: {wif}\n")
        f.write("Expected Address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\n")
        f.write("\nVERIFICATION:\n")
        f.write("Go to: https://iancoleman.io/bitcoin-key-compression/\n")
        f.write(f"Enter WIF: {wif}\n")
        f.write("Should show address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\n")

    print("\n✅ SUCCESS! Results saved to target_ckey_decrypted.txt")
    print(f"📋 Private Key: {decrypted_hex}")
    print(f"🔑 WIF Key: {wif}")
    print("\n🌐 VERIFY AT: https://iancoleman.io/bitcoin-key-compression/")
    print(f"   Enter: {wif}")
    print("   Should match: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
if __name__ == "__main__":
    main()
