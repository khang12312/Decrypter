#!/usr/bin/env python3
"""
Flexible Bitcoin Wallet Decryptor
================================
This version can handle various scenarios:
1. Automatic ckey detection in wallet files
2. Manual ckey input for testing
3. Multiple decryption strategies

Usage:
    python flexible_decryptor.py                    # Interactive mode
    python flexible_decryptor.py auto               # Automatic mode
    python flexible_decryptor.py manual             # Manual input mode
"""

import sys
import os
import hashlib
import base58
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii

def sha256(data):
    return hashlib.sha256(data).digest()

def double_sha256(data):
    return sha256(sha256(data))

def base58check_encode(payload):
    checksum = double_sha256(payload)[:4]
    return base58.b58encode(payload + checksum).decode('utf-8')

class FlexibleDecryptor:
    def __init__(self):
        self.master_key = "0399571599931743677e2264a2523c2c031ce23c213ee9bc6342ed62ec6ed613"

    def read_wallet_file(self, file_path):
        """Read wallet file as binary"""
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"❌ Error reading wallet file: {e}")
            return b''

    def find_potential_ckeys(self, data):
        """Find potential ckeys in binary data"""
        ckeys = []

        # Look for compressed public keys (33 bytes starting with 02 or 03)
        for i in range(len(data) - 49):  # 33 + 16 bytes minimum
            if data[i] in [0x02, 0x03]:
                pubkey_candidate = data[i:i+33]
                if len(pubkey_candidate) == 33:
                    # Look for 16 bytes of encrypted data after pubkey
                    encrypted_candidate = data[i+33:i+49]
                    if len(encrypted_candidate) == 16:
                        ckeys.append({
                            'pubkey': pubkey_candidate.hex(),
                            'encrypted': encrypted_candidate.hex(),
                            'offset': i
                        })

        return ckeys

    def try_decrypt_ckey(self, pubkey_hex, encrypted_hex):
        """Try to decrypt a ckey with various strategies"""
        try:
            pubkey_bytes = bytes.fromhex(pubkey_hex)
            encrypted_bytes = bytes.fromhex(encrypted_hex)
            master_bytes = bytes.fromhex(self.master_key)

            # Generate IV from pubkey
            iv_full = double_sha256(pubkey_bytes).hex()
            iv = iv_full[:32]
            iv_bytes = bytes.fromhex(iv)

            print(f"  IV: {iv}")

            # Decrypt
            cipher = Cipher(algorithms.AES(master_bytes), modes.CBC(iv_bytes), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()

            print(f"  Raw decrypted: {decrypted_padded.hex()}")

            # Try different padding removal strategies
            results = []

            # Strategy 1: No padding
            if len(decrypted_padded) == 32:
                results.append(('no_padding', decrypted_padded.hex()))

            # Strategy 2: PKCS#7 padding
            if len(decrypted_padded) > 0:
                padding_len = decrypted_padded[-1]
                if 1 <= padding_len <= 16:
                    padding_bytes = decrypted_padded[-padding_len:]
                    if all(b == padding_len for b in padding_bytes):
                        unpadded = decrypted_padded[:-padding_len]
                        if len(unpadded) == 32:
                            results.append(('pkcs7', unpadded.hex()))

            # Strategy 3: Extract 32 bytes from different positions
            for offset in range(min(16, len(decrypted_padded) - 32 + 1)):
                candidate = decrypted_padded[offset:offset+32]
                if len(candidate) == 32:
                    results.append((f'offset_{offset}', candidate.hex()))

            return results

        except Exception as e:
            print(f"  ❌ Decryption error: {e}")
            return []

    def generate_wif(self, private_key_hex):
        """Generate WIF from private key"""
        try:
            private_bytes = bytes.fromhex(private_key_hex)

            # Try both compressed and uncompressed
            extended_uncompressed = b'\x80' + private_bytes
            wif_uncompressed = base58check_encode(extended_uncompressed)

            extended_compressed = b'\x80' + private_bytes + b'\x01'
            wif_compressed = base58check_encode(extended_compressed)

            return {
                'uncompressed': wif_uncompressed,
                'compressed': wif_compressed
            }
        except Exception as e:
            print(f"  ❌ WIF generation error: {e}")
            return None

    def interactive_mode(self):
        """Interactive mode for step-by-step decryption"""
        print("🔧 Interactive Bitcoin Wallet Decryptor")
        print("=" * 50)

        wallet_file = input("Enter wallet file path (or press Enter for default): ").strip()
        if not wallet_file:
            wallet_file = "Client-DAta/wallet.dat.txt"

        if not os.path.exists(wallet_file):
            print(f"❌ File not found: {wallet_file}")
            return

        print(f"📁 Using wallet file: {wallet_file}")

        # Ask for ckey input method
        print("\nHow would you like to input ckey data?")
        print("1. Automatic detection from wallet file")
        print("2. Manual input from instructions")
        print("3. Manual hex input")

        choice = input("Choose (1-3): ").strip()

        if choice == "1":
            self.auto_detection_mode(wallet_file)
        elif choice == "2":
            self.manual_from_instructions()
        elif choice == "3":
            self.manual_hex_input()
        else:
            print("❌ Invalid choice")

    def auto_detection_mode(self, wallet_file):
        """Automatic ckey detection and decryption"""
        print("\n🔍 Automatic ckey detection...")

        data = self.read_wallet_file(wallet_file)
        if not data:
            return

        ckeys = self.find_potential_ckeys(data)

        if not ckeys:
            print("❌ No potential ckeys found")
            return

        print(f"✅ Found {len(ckeys)} potential ckeys")

        # Try to decrypt each ckey
        successful_decryptions = []

        for i, ckey in enumerate(ckeys[:10]):  # Limit to first 10 for testing
            print(f"\n🔐 Trying ckey {i+1}:")
            print(f"  Pubkey: {ckey['pubkey'][:20]}...")
            print(f"  Encrypted: {ckey['encrypted'][:20]}...")

            decryption_results = self.try_decrypt_ckey(ckey['pubkey'], ckey['encrypted'])

            for strategy, private_key in decryption_results:
                print(f"  ✅ Strategy '{strategy}': {private_key}")

                wifs = self.generate_wif(private_key)
                if wifs:
                    print(f"    WIF uncompressed: {wifs['uncompressed']}")
                    print(f"    WIF compressed: {wifs['compressed']}")

                    successful_decryptions.append({
                        'pubkey': ckey['pubkey'],
                        'private_key': private_key,
                        'strategy': strategy,
                        'wifs': wifs
                    })

        if successful_decryptions:
            print("\n✅ Found successful decryptions!")
            self.save_results(successful_decryptions)
        else:
            print("\n❌ No successful decryptions found")

    def manual_from_instructions(self):
        """Manual decryption using exact values from instructions"""
        print("\n📋 Manual decryption using instructions data")

        # Exact values from instructions
        pubkey = "0382ca08ce78b0935099c74db12873a7dc1cba10a44165ce8cc1d0602f49ee97f5"
        encrypted = "2e24da42feb389aab372163cac88c5b9233d6f1a2e6bcb4e8337dfa21f0aa85309fa70c00637474a88b0d881c4d93155"
        expected_private = "3ea5eaabe7f7b997ce732acc9cf08315a805109003ce2bd918bac1b73b82d7b7"

        print(f"Pubkey: {pubkey}")
        print(f"Encrypted: {encrypted}")

        decryption_results = self.try_decrypt_ckey(pubkey, encrypted)

        for strategy, private_key in decryption_results:
            print(f"✅ Strategy '{strategy}': {private_key}")

            if private_key == expected_private:
                print("🎉 SUCCESS: Matches expected private key!")
            else:
                print(f"❌ Does not match expected: {expected_private}")

            wifs = self.generate_wif(private_key)
            if wifs:
                print(f"  WIF uncompressed: {wifs['uncompressed']}")
                print(f"  WIF compressed: {wifs['compressed']}")

    def manual_hex_input(self):
        """Manual hex input for testing"""
        print("\n📝 Manual hex input mode")

        pubkey = input("Enter pubkey (hex): ").strip()
        encrypted = input("Enter encrypted private key (hex): ").strip()

        if len(pubkey) != 66 or len(encrypted) != 64:
            print("❌ Invalid lengths. Expected: pubkey=66 chars, encrypted=64 chars")
            return

        decryption_results = self.try_decrypt_ckey(pubkey, encrypted)

        for strategy, private_key in decryption_results:
            print(f"✅ Strategy '{strategy}': {private_key}")

            wifs = self.generate_wif(private_key)
            if wifs:
                print(f"  WIF uncompressed: {wifs['uncompressed']}")
                print(f"  WIF compressed: {wifs['compressed']}")

    def save_results(self, results):
        """Save decryption results to file"""
        with open('flexible_decryption_results.txt', 'w') as f:
            f.write("FLEXIBLE BITCOIN WALLET DECRYPTION RESULTS\n")
            f.write("=" * 60 + "\n")
            f.write(f"Master Key: {self.master_key}\n")
            f.write(f"Timestamp: {os.times()}\n\n")

            for i, result in enumerate(results, 1):
                f.write(f"Result {i}:\n")
                f.write(f"  Pubkey: {result['pubkey']}\n")
                f.write(f"  Private Key: {result['private_key']}\n")
                f.write(f"  Strategy: {result['strategy']}\n")
                f.write(f"  WIF Uncompressed: {result['wifs']['uncompressed']}\n")
                f.write(f"  WIF Compressed: {result['wifs']['compressed']}\n")
                f.write("-" * 60 + "\n")

        print(f"\n💾 Results saved to flexible_decryption_results.txt")

def main():
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        decryptor = FlexibleDecryptor()

        if mode == "auto":
            wallet_file = sys.argv[2] if len(sys.argv) > 2 else "Client-DAta/wallet.dat.txt"
            decryptor.auto_detection_mode(wallet_file)
        elif mode == "manual":
            decryptor.manual_from_instructions()
        elif mode == "hex":
            decryptor.manual_hex_input()
        else:
            print("❌ Invalid mode. Use: auto, manual, or hex")
    else:
        decryptor = FlexibleDecryptor()
        decryptor.interactive_mode()

if __name__ == "__main__":
    main()
