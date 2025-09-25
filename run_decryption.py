#!/usr/bin/env python3
"""
One-click Bitcoin wallet decryptor
=================================
This convenience script wraps the existing `EnhancedBitcoinWalletDecryptor` class
(from `wallet_decryptor.py`) so that you can immediately decrypt every `ckey`
found in the sample data shipped under `Client-DAta/wallet.dat.txt`.

Usage:
    python run_decryption.py          # uses default sample wallet
    python run_decryption.py <path>   # decrypt a specific wallet file

Results are displayed on-screen and simultaneously written to
`decrypted_wifs_<timestamp>.txt` in the current directory.
"""
import os
import sys
import datetime
from wallet_decryptor import EnhancedBitcoinWalletDecryptor

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

    print("🚀 Starting bulk decryption …\n")

    decryptor = EnhancedBitcoinWalletDecryptor(MASTER_KEY)
    results = decryptor.process_wallet_enhanced(wallet_file)

    if not results:
        print("\n❌ No keys could be decrypted – please double-check the master key and input file.")
        sys.exit(2)

    # Persist results for the client
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = f"decrypted_wifs_{timestamp}.txt"
    with open(out_file, "w", encoding="utf-8") as fh:
        fh.write("# Decrypted Bitcoin WIF keys\n")
        fh.write(f"# Wallet file : {wallet_file}\n")
        fh.write(f"# Master key  : {MASTER_KEY}\n")
        fh.write(f"# Created on  : {timestamp}\n\n")
        for i, entry in enumerate(results, 1):
            fh.write(f"Key {i}\n")
            fh.write("-" * 60 + "\n")
            for k, v in entry.items():
                fh.write(f"{k:20}: {v}\n")
            fh.write("\n")

    print(f"\n💾 All keys saved to {out_file}")
    print("   You can verify any WIF at https://iancoleman.io/bitcoin-key-compression/\n")

if __name__ == "__main__":
    main()
