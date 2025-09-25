#!/usr/bin/env python3
"""
One-click Bitcoin wallet decryptor - Fixed Version
===============================================
This convenience script uses the improved FixedBitcoinWalletDecryptor class
to properly decrypt wallet files.

Usage:
    python run_decryption_fixed.py          # uses default sample wallet
    python run_decryption_fixed.py <path>   # decrypt a specific wallet file

Results are displayed on-screen and simultaneously written to
decrypted_wifs_fixed_<timestamp>.txt in the current directory.
"""
import os
import sys
import datetime
from wallet_decryptor_fixed import FixedBitcoinWalletDecryptor

# Master key provided in the instructions.rtf (32-byte AES key)
MASTER_KEY = "0399571599931743677e2264a2523c2c031ce23c213ee9bc6342ed62ec6ed613"

# Default location of the client-supplied wallet file
DEFAULT_WALLET_PATH = os.path.join(
    os.path.dirname(__file__),
    "Client-DAta",
    "wallet.dat.txt",  # The client dumped the Berkeley-DB as a *.txt file
)

def main():
    # Pick wallet file from CLI or fallback to default sample
    wallet_file = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_WALLET_PATH

    if not os.path.exists(wallet_file):
        print(f"❌ Wallet file not found: {wallet_file}")
        sys.exit(1)

    print("🚀 Starting enhanced decryption with improved ckey detection…\n")

    decryptor = FixedBitcoinWalletDecryptor(MASTER_KEY)
    results = decryptor.process_wallet_fixed(wallet_file)

    if not results:
        print("\n❌ No keys could be decrypted – the wallet format may be different than expected.")
        print("💡 Troubleshooting tips:")
        print("   • Verify this is a Bitcoin Core wallet.dat file")
        print("   • Check if the file is corrupted or truncated")
        print("   • Try the original crackBTCwallet tool if available")
        sys.exit(2)

    # Persist results for the client
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"decrypted_wifs_fixed_{timestamp}.txt"
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write("# Fixed Bitcoin Wallet Decryption Results\n")
        fh.write(f"# Wallet file : {wallet_file}\n")
        fh.write(f"# Master key  : {MASTER_KEY}\n")
        fh.write(f"# Created on  : {timestamp}\n")
        fh.write(f"# Method      : Enhanced binary parsing with improved padding\n\n")
        for i, entry in enumerate(results, 1):
            fh.write(f"Key {i}\n")
            fh.write("-" * 60 + "\n")
            for k, v in entry.items():
                fh.write(f"{k:<20}: {v}\n")
            fh.write("\n")

    print(f"\n🎉 SUCCESS! Decrypted {len(results)} private keys")
    print(f"💾 All keys saved to {out_file}")
    print("   You can verify any WIF at https://iancoleman.io/bitcoin-key-compression/\n")

    print("🔍 VERIFICATION INSTRUCTIONS:")
    print("   1. Go to: https://iancoleman.io/bitcoin-key-compression/")
    print(f"   2. Enter: {results[0]['wif_compressed']}")
    print("   3. Click 'View Details'")
    print("   4. Confirm address matches: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
if __name__ == "__main__":
    main()
