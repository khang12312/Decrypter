#!/usr/bin/env python3
"""
Bitcoin Wallet Decryption Tool
Implements the functionality of crackBTCwallet for Windows
Extracts and decrypts ckeys from wallet.dat using known master key

Author: Irfan Khan
Date: 2025-09-23
Version: 2.0 (Enhanced)
License: MIT
Description: Advanced tool for decrypting ckeys from wallet.dat file using known master key
Usage: python wallet_decryptor.py <wallet_file>
Example: python wallet_decryptor.py wallet.dat
"""

import sys
import os
import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base58
import binascii
import re
import logging
from typing import List, Dict, Optional, Tuple
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def sha256(data):
    """SHA256 hash function"""
    return hashlib.sha256(data).digest()

def double_sha256(data):
    """Double SHA256 hash"""
    return sha256(sha256(data))

def hash160(data):
    """RIPEMD-160 hash of SHA256"""
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256(data))
    return ripemd160.digest()

def base58check_encode(payload):
    """Base58Check encode"""
    checksum = double_sha256(payload)[:4]
    return base58.b58encode(payload + checksum).decode('utf-8')

class EnhancedBitcoinWalletDecryptor:
    def __init__(self, master_key_hex):
        self.master_key = bytes.fromhex(master_key_hex)
        self.ckeys_found = []
        self.addresses_found = []

    def try_decode_file(self, file_path: str) -> bytes:
        """
        Try different encodings to read the wallet file
        """
        encodings_to_try = ['utf-8', 'latin-1', 'cp1252', 'utf-16', 'utf-16le', 'utf-16be']

        for encoding in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    content = f.read()
                logger.info(f"Successfully decoded file with {encoding} encoding")
                return content.encode('latin-1')  # Convert back to bytes for binary processing
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.warning(f"Error reading with {encoding}: {e}")
                continue

        # If all encodings fail, try reading as binary
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read file as binary: {e}")
            return b''

    def extract_ckeys_enhanced(self, wallet_file_path: str) -> List[Dict]:
        """
        Enhanced ckey extraction with multiple parsing strategies
        """
        ckeys = []
        addresses = []

        try:
            # Try different approaches to read the file
            data = self.try_decode_file(wallet_file_path)
            if not data:
                logger.error("Could not read wallet file")
                return [], []

            logger.info(f"Read {len(data)} bytes from wallet file")

            # Strategy 1: Look for ckey patterns (original method)
            data_str = data.decode('latin-1', errors='ignore')
            ckeys.extend(self._extract_ckeys_regex(data_str))

            # Strategy 2: Look for hex patterns that might be ckeys
            ckeys.extend(self._extract_ckeys_hex_pattern(data))

            # Strategy 3: Parse as potential BDB format
            addresses.extend(self._extract_addresses_from_data(data))

            logger.info(f"Found {len(ckeys)} ckeys and {len(addresses)} addresses")
            return ckeys, addresses

        except Exception as e:
            logger.error(f"Error in enhanced extraction: {e}")
            logger.error(traceback.format_exc())
            return [], []

    def _extract_ckeys_regex(self, data_str: str) -> List[Dict]:
        """Extract ckeys using regex patterns"""
        ckeys = []

        # Pattern 1: Standard ckey format
        pattern1 = r'ckey\s+([0-9a-fA-F]{66})\s*([0-9a-fA-F]{64})'
        matches1 = re.findall(pattern1, data_str, re.IGNORECASE | re.MULTILINE)

        for pubkey, encrypted_privkey in matches1:
            if len(pubkey) == 66 and len(encrypted_privkey) == 64:
                ckeys.append({
                    'pubkey': pubkey,
                    'encrypted_privkey': encrypted_privkey,
                    'source': 'regex_pattern1'
                })

        # Pattern 2: More flexible pattern
        pattern2 = r'ckey\s+([0-9a-fA-F]{64,68})\s*([0-9a-fA-F]{64,128})'
        matches2 = re.findall(pattern2, data_str, re.IGNORECASE | re.MULTILINE)

        for pubkey, encrypted_privkey in matches2:
            # Clean and validate
            pubkey = pubkey.strip()
            encrypted_privkey = encrypted_privkey.strip()
            if len(pubkey) == 66 and len(encrypted_privkey) == 64:
                # Check if not already found
                if not any(ckey['pubkey'] == pubkey for ckey in ckeys):
                    ckeys.append({
                        'pubkey': pubkey,
                        'encrypted_privkey': encrypted_privkey,
                        'source': 'regex_pattern2'
                    })

        return ckeys

    def _extract_ckeys_hex_pattern(self, data: bytes) -> List[Dict]:
        """Enhanced hex pattern extraction with better validation"""
        ckeys = []

        # Look for sequences of hex digits that match ckey pattern
        hex_data = data.hex()

        # Pattern for pubkey (66 hex) followed by encrypted privkey (96 hex, 48 bytes)
        # This is more restrictive and looks for the actual BDB record structure
        pattern = r'([0-9a-fA-F]{66})([0-9a-fA-F]{96})'

        matches = re.findall(pattern, hex_data)

        for pubkey, encrypted_privkey in matches:
            # Strict validation for legitimate Bitcoin ckeys
            if not self._is_valid_ckey(pubkey, encrypted_privkey):
                continue

            ckeys.append({
                'pubkey': pubkey,
                'encrypted_privkey': encrypted_privkey,
                'source': 'hex_pattern'
            })

        return ckeys

    def _is_valid_ckey(self, pubkey: str, encrypted_privkey: str) -> bool:
        """Validate if a pubkey + encrypted_privkey pair is a legitimate Bitcoin ckey"""
        try:
            # Pubkey must be exactly 66 hex characters (33 bytes)
            if len(pubkey) != 66:
                return False

            # Pubkey must start with 02 or 03 (compressed public key)
            if not pubkey.startswith(('02', '03')):
                return False

            # Encrypted private key must be exactly 96 hex characters (48 bytes) as stored in wallet.dat
            if len(encrypted_privkey) != 96:
                return False

            # Additional validation: check if encrypted key contains only valid hex
            int(pubkey, 16)
            int(encrypted_privkey, 16)

            # Check if pubkey represents a valid EC point (basic validation)
            pubkey_bytes = bytes.fromhex(pubkey)
            if len(pubkey_bytes) != 33:
                return False

            return True

        except (ValueError, TypeError):
            return False

    def _extract_ckeys_bdb_format(self, data: bytes) -> List[Dict]:
        """Extract ckeys from actual Berkeley DB format"""
        ckeys = []

        try:
            # Bitcoin wallet.dat uses Berkeley DB format
            # Look for BDB record headers and key-value pairs
            # This is a simplified version - real BDB parsing is complex

            # Look for patterns that might be BDB records containing ckeys
            # BDB records often have headers like: [length][key][value]

            # Pattern 1: Look for ckey records with BDB structure
            # This searches for the pattern: ckey + 33-byte pubkey + 16-byte encrypted key
            bdb_pattern = b'ckey([\\x02\\x03][\\s\\S]{31})([\\s\\S]{16})'

            matches = re.findall(bdb_pattern, data, re.IGNORECASE)

            for pubkey_bytes, encrypted_bytes in matches:
                try:
                    pubkey = pubkey_bytes.hex()
                    encrypted_privkey = encrypted_bytes.hex()

                    if self._is_valid_ckey(pubkey, encrypted_privkey):
                        ckeys.append({
                            'pubkey': pubkey,
                            'encrypted_privkey': encrypted_privkey,
                            'source': 'bdb_format'
                        })
                except:
                    continue

            # Pattern 2: Look for raw hex patterns in a more structured way
            # Look for sequences where we have 33 bytes starting with 02/03 followed by 16 bytes
            for i in range(len(data) - 49):  # 33 + 16 bytes
                potential_pubkey = data[i:i+33]
                potential_encrypted = data[i+33:i+49]

                if (len(potential_pubkey) == 33 and
                    len(potential_encrypted) == 16 and
                    potential_pubkey[0] in [0x02, 0x03]):

                    try:
                        pubkey = potential_pubkey.hex()
                        encrypted_privkey = potential_encrypted.hex()

                        if self._is_valid_ckey(pubkey, encrypted_privkey):
                            ckeys.append({
                                'pubkey': pubkey,
                                'encrypted_privkey': encrypted_privkey,
                                'source': 'bdb_raw'
                            })
                    except:
                        continue

        except Exception as e:
            logger.warning(f"BDB extraction error: {e}")

        return ckeys

    def extract_ckeys_enhanced(self, wallet_file_path: str) -> List[Dict]:
        """
        Enhanced ckey extraction with multiple parsing strategies
        """
        ckeys = []
        addresses = []

        try:
            # Try different approaches to read the file
            data = self.try_decode_file(wallet_file_path)
            if not data:
                logger.error("Could not read wallet file")
                return [], []

            logger.info(f"Read {len(data)} bytes from wallet file")

            # Strategy 1: Look for ckey patterns (original method)
            data_str = data.decode('latin-1', errors='ignore')
            ckeys.extend(self._extract_ckeys_regex(data_str))

            # Strategy 2: Enhanced hex pattern matching with validation
            ckeys.extend(self._extract_ckeys_hex_pattern(data))

            # Strategy 3: Berkeley DB format parsing
            ckeys.extend(self._extract_ckeys_bdb_format(data))

            # Strategy 4: Parse as potential BDB format - look for record structures
            addresses.extend(self._extract_addresses_from_data(data))

            # Remove duplicates based on pubkey
            seen_pubkeys = set()
            unique_ckeys = []

            for ckey in ckeys:
                if ckey['pubkey'] not in seen_pubkeys:
                    seen_pubkeys.add(ckey['pubkey'])
                    unique_ckeys.append(ckey)

            logger.info(f"Found {len(unique_ckeys)} unique ckeys and {len(addresses)} addresses")
            return unique_ckeys, addresses

        except Exception as e:
            logger.error(f"Error in enhanced extraction: {e}")
            logger.error(traceback.format_exc())
            return [], []

    def _extract_addresses_from_data(self, data: bytes) -> List[str]:
        """Extract potential Bitcoin addresses from wallet data"""
        addresses = []

        # Look for base58 patterns that could be addresses
        data_str = data.decode('latin-1', errors='ignore')

        # Bitcoin address pattern (starts with 1, 26-35 chars, base58)
        address_pattern = r'\b1[1-9A-HJ-NP-Za-km-z]{25,34}\b'
        matches = re.findall(address_pattern, data_str)

        for match in matches:
            if self._validate_bitcoin_address(match):
                addresses.append(match)

        return list(set(addresses))  # Remove duplicates

    def _validate_bitcoin_address(self, address: str) -> bool:
        """Validate if a string is a valid Bitcoin address"""
        try:
            # Decode base58
            decoded = base58.b58decode(address)

            # Check length and version
            if len(decoded) == 25 and decoded[0] == 0x00:
                # Verify checksum
                checksum = double_sha256(decoded[:21])[:4]
                return decoded[21:] == checksum
            return False
        except:
            return False

    def decrypt_private_key(self, encrypted_privkey_hex: str, iv_hex: str) -> Optional[str]:
        """
        Enhanced private key decryption with better error handling and validation
        """
        try:
            encrypted_key = bytes.fromhex(encrypted_privkey_hex)
            iv = bytes.fromhex(iv_hex)

            # Validate lengths
            # Encrypted key must be a multiple of 16 bytes (AES block size) and
            # in Bitcoin Core wallet.dat it is 48 bytes (96 hex characters)
            if len(encrypted_key) % 16 != 0:
                logger.warning(f"Unexpected encrypted key length: {len(encrypted_key)} bytes (expected 48 or another multiple of 16)")
                return None

            if len(iv) != 16:
                logger.warning(f"Unexpected IV length: {len(iv)} bytes (expected 16)")
                return None

            if len(self.master_key) != 32:
                logger.error(f"Invalid master key length: {len(self.master_key)} bytes (expected 32)")
                return None

            # Create AES cipher
            cipher = Cipher(algorithms.AES(self.master_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            # Decrypt
            decrypted_padded = decryptor.update(encrypted_key) + decryptor.finalize()

            # Remove PKCS#7 padding
            if len(decrypted_padded) > 0:
                padding_length = decrypted_padded[-1]

                # Validate padding
                if padding_length > 0 and padding_length <= 16:
                    # Check if padding is valid (all bytes are the padding value)
                    padding_bytes = decrypted_padded[-padding_length:]
                    if all(b == padding_length for b in padding_bytes):
                        decrypted = decrypted_padded[:-padding_length]
                        return decrypted.hex()
                    else:
                        logger.warning("Invalid PKCS#7 padding detected")
                elif padding_length == 0:
                    # No padding, assume raw private key
                    logger.info("No padding detected, treating as raw private key")
                    return decrypted_padded.hex()
                else:
                    logger.warning(f"Invalid padding length: {padding_length}")

            # If no valid padding, try to return as-is and let WIF conversion validate
            logger.info("Attempting decryption without padding removal")
            return decrypted_padded.hex()

        except ValueError as e:
            logger.error(f"Hex decoding error: {e}")
            return None
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            logger.error(f"Debug info - Encrypted: {encrypted_privkey_hex[:32]}..., IV: {iv_hex[:32]}..., Master: {self.master_key.hex()[:16]}...")
            return None

    def private_key_to_wif(self, private_key_hex: str, compressed: bool = True) -> Optional[str]:
        """
        Convert hex private key to WIF format with validation
        """
        try:
            private_key_bytes = bytes.fromhex(private_key_hex)

            if len(private_key_bytes) != 32:
                logger.warning(f"Private key length is {len(private_key_bytes)}, expected 32")
                return None

            # Add version byte (0x80 for mainnet)
            extended_key = b'\x80' + private_key_bytes

            # Add compression flag if needed
            if compressed:
                extended_key += b'\x01'

            return base58check_encode(extended_key)

        except ValueError as e:
            logger.error(f"Private key hex error: {e}")
            return None
        except Exception as e:
            logger.error(f"WIF conversion error: {e}")
            return None

    def process_wallet_enhanced(self, wallet_file_path: str) -> List[Dict]:
        """
        Enhanced main processing function
        """
        print("Enhanced Bitcoin Wallet Decryptor")
        print("=" * 50)
        print(f"Master Key: {self.master_key.hex()}")
        print(f"Wallet File: {wallet_file_path}")
        print("=" * 50)

        # Extract ckeys and addresses
        ckeys, addresses = self.extract_ckeys_enhanced(wallet_file_path)
        if not ckeys:
            print("❌ No ckeys found in wallet file")
            print("Possible reasons:")
            print("1. Wallet file is encrypted or corrupted")
            print("2. Different wallet format than expected")
            print("3. File encoding issues")
            return []

        print(f"✅ Found {len(ckeys)} ckeys and {len(addresses)} addresses")

        if addresses:
            print("\n📍 Addresses found in wallet:")
            for i, addr in enumerate(addresses[:5], 1):  # Show first 5
                print(f"  {i}. {addr}")
            if len(addresses) > 5:
                print(f"  ... and {len(addresses) - 5} more")

        results = []

        for i, ckey in enumerate(ckeys):
            print(f"\n🔐 Processing ckey {i+1}/{len(ckeys)}")
            print(f"   Source: {ckey['source']}")
            print(f"   Pubkey: {ckey['pubkey']}")

            # Generate IV from pubkey (first 32 chars of double SHA256)
            # IV is first 16 bytes (32 hex chars) of double SHA256 of raw pubkey bytes
            iv_hash = double_sha256(bytes.fromhex(ckey['pubkey'])).hex()
            iv = iv_hash[:32]

            print(f"   IV: {iv}")

            # Decrypt private key
            decrypted_privkey = self.decrypt_private_key(ckey['encrypted_privkey'], iv)
            if not decrypted_privkey:
                print(f"   ❌ Failed to decrypt private key")
                continue

            print(f"   ✅ Decrypted private key: {decrypted_privkey}")

            # Convert to WIF
            wif_compressed = self.private_key_to_wif(decrypted_privkey, compressed=True)
            wif_uncompressed = self.private_key_to_wif(decrypted_privkey, compressed=False)

            if not wif_compressed:
                print(f"   ❌ Failed to convert to WIF")
                continue

            print(f"   ✅ WIF (compressed): {wif_compressed}")
            if wif_uncompressed:
                print(f"   ✅ WIF (uncompressed): {wif_uncompressed}")

            results.append({
                'pubkey': ckey['pubkey'],
                'decrypted_privkey': decrypted_privkey,
                'wif_uncompressed': wif_uncompressed,
                'wif_compressed': wif_compressed,
                'source': ckey['source']
            })

        return results

    def verify_wif_online_demo(self, wif_key: str, expected_address: str) -> bool:
        """
        Demonstrate WIF verification process
        """
        print("\n🔍 ONLINE VERIFICATION DEMONSTRATION:")
        print(f"   WIF Key: {wif_key}")
        print(f"   Expected Address: {expected_address}")
        print("   ")
        print("   To verify:")
        print("   1. Go to: https://iancoleman.io/bitcoin-key-compression/")
        print(f"   2. Enter: {wif_key}")
        print("   3. Click 'View Details'")
        print(f"   4. Confirm address matches: {expected_address}")

        return True

def main():
    if len(sys.argv) != 2:
        print("Usage: python wallet_decryptor.py <wallet_file>")
        print("Example: python wallet_decryptor.py wallet.dat")
        sys.exit(1)

    wallet_file = sys.argv[1]

    if not os.path.exists(wallet_file):
        print(f"❌ Wallet file not found: {wallet_file}")
        sys.exit(1)

    # Master key from instructions
    master_key = "0399571599931743677e2264a2523c2c031ce23c213ee9bc6342ed62ec6ed613"

    decryptor = EnhancedBitcoinWalletDecryptor(master_key)

    # Process wallet
    results = decryptor.process_wallet_enhanced(wallet_file)

    print("\n📊 SUMMARY:")
    print("=" * 50)
    print(f"   Total ckeys processed: {len(results)}")

    if results:
        print("\n💰 DECRYPTED WIF KEYS:")
        for i, result in enumerate(results, 1):
            print(f"   {i}. {result['wif_compressed']}")

        # Save results to file
        with open('decrypted_wifs.txt', 'w') as f:
            f.write("ENHANCED BITCOIN WALLET DECRYPTION RESULTS\n")
            f.write("=" * 50 + "\n")
            f.write(f"Master Key: {master_key}\n")
            f.write(f"Wallet File: {wallet_file}\n")
            f.write("Timestamp: Decrypted on demand\n\n")

            for i, result in enumerate(results, 1):
                f.write(f"Key {i}:\n")
                f.write(f"  Pubkey: {result['pubkey']}\n")
                f.write(f"  Private Key: {result['decrypted_privkey']}\n")
                f.write(f"  WIF Compressed: {result['wif_compressed']}\n")
                f.write(f"  WIF Uncompressed: {result['wif_uncompressed']}\n")
                f.write(f"  Source: {result['source']}\n")
                f.write("-" * 50 + "\n")

        print("\n💾 Results saved to: decrypted_wifs.txt")
        # Demonstrate verification
        if results:
            decryptor.verify_wif_online_demo(
                results[0]['wif_compressed'],
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
            )
    else:
        print("❌ No WIF keys were successfully decrypted")

if __name__ == "__main__":
    main()
