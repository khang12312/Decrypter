#!/usr/bin/env python3
"""
Verify WIFs by deriving real Bitcoin P2PKH addresses (reverse check).

Requirements:
- Python package `ecdsa` (pure Python). If not installed, run:
    pip install ecdsa

Usage:
    python verify_wifs_real.py                 # verifies a built-in sample list
    python verify_wifs_real.py <wif1> <wif2>   # verify specific WIFs passed via CLI

This script decodes WIF, detects compressed/uncompressed, derives the public key
on secp256k1, hashes to a P2PKH address, and prints results.
"""
import sys
import hashlib
import base58

try:
    import ecdsa
except ImportError:
    print("❌ Missing dependency: ecdsa. Please install it with: pip install ecdsa")
    sys.exit(1)

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(b)
    return h.digest()

def base58check_encode(payload: bytes) -> str:
    checksum = sha256(sha256(payload))[:4]
    return base58.b58encode(payload + checksum).decode('utf-8')

def base58check_decode(s: str) -> bytes:
    raw = base58.b58decode(s)
    data, checksum = raw[:-4], raw[-4:]
    if sha256(sha256(data))[:4] != checksum:
        raise ValueError("Invalid Base58Check checksum")
    return raw

def wif_to_privkey(wif: str):
    raw = base58check_decode(wif)
    if raw[0] != 0x80:
        raise ValueError("Not a mainnet WIF (0x80)")
    # compressed if extra 0x01 before checksum
    if len(raw) == 38 and raw[-5] == 0x01:
        compressed = True
        priv = raw[1:-5]
    elif len(raw) == 37:
        compressed = False
        priv = raw[1:-4]
    else:
        # Fallback parsing
        compressed = (raw[-5] == 0x01)
        priv = raw[1:-5] if compressed else raw[1:-4]
    if len(priv) != 32:
        raise ValueError(f"Unexpected private key length: {len(priv)}")
    return priv, compressed

def privkey_to_pubkey(priv: bytes, compressed: bool) -> bytes:
    sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    x = vk.pubkey.point.x()
    y = vk.pubkey.point.y()
    x_bytes = x.to_bytes(32, 'big')
    if compressed:
        prefix = b"\x02" if (y % 2 == 0) else b"\x03"
        return prefix + x_bytes
    else:
        y_bytes = y.to_bytes(32, 'big')
        return b"\x04" + x_bytes + y_bytes

def pubkey_to_p2pkh_address(pubkey_bytes: bytes) -> str:
    pubkey_hash = ripemd160(sha256(pubkey_bytes))
    payload = b"\x00" + pubkey_hash  # 0x00 mainnet P2PKH
    return base58check_encode(payload)

def verify_wif_list(wifs):
    for i, wif in enumerate(wifs, 1):
        try:
            priv, is_comp = wif_to_privkey(wif)
            pub = privkey_to_pubkey(priv, is_comp)
            addr = pubkey_to_p2pkh_address(pub)
            print(f"[{i}] WIF: {wif}")
            print(f"    Compressed : {is_comp}")
            print(f"    PrivKey   : {priv.hex()}")
            print(f"    PubKey    : {pub.hex()[:20]}... ({len(pub)} bytes)")
            print(f"    Address   : {addr}\n")
        except Exception as e:
            print(f"[{i}] WIF: {wif}")
            print(f"    ❌ Error: {e}\n")

def main():
    if len(sys.argv) > 1:
        wifs = sys.argv[1:]
    else:
        # Sample WIFs from your provided snippet
        wifs = [
            "KyHrExpc236DfoUH443NqmvLkR6dCVR9dp2JJ1JR65NPrpMiM7Wh",
            "5JHWHJdcaK9S5G4TkHYodsxavnngU5B19LiXeqZ3HZFpKbUH37w",
            "L5Zvh996hg8cQcneJXZLsyj8t118aBcVcmxuick8At4T1wKSvTML",
            "5KhzUg12HvGmj48Ap22tdUMRSbtgn8PYQWfwzTgDxFjvUS2P4Ef",
            "Kyj2NqH6YByW3qGpYPs89KptSTYaRpnuHvhyAWWriLsBeY2Pez4r",
            "5JPD6QAzSeNs5ikTdZpc9gcKTABnBcJCPsEMt6KzwE7PMHxZbJH",
            "L1rVRuKmspkWV5jCVkbAzWyQ5Ze7KTqoHrvzfcNAi8KfrWhHymwa",
            "5JsBX7RC5GMHCM6wG8A6tYiKphvim4N2RfVzvcCbNZ24NFNRMii",
            "KzUA7aE27yVDaWVDCWLYVNEz2sJu1PfsJZ9DVnsi8tQwFGz3eY69",
            "5JYytnbDVKEeHewso7CE2Sf4QXtBRZKmvpcPmaxSdgHkZGoNyfJ",
            "L49JtsMuZvBTEXxYxREcSWbvepNHLJdF5DMHRcxBMyLtyV1ns8hv",
            "5KPGqTN3r9Ra8bexj1WNArkiA2DXSDbwqzB2uhmg3wTFx1ymDFi",
            "L3c7uHXRALpXJGTJSPKsANxaEuWmTFTB64qrkXQVeUnbSBoE1Lmd",
            "5KGCzABWwgP6WHeE1mUqXDgKrphGxnsLWF1eZ4iaE2K2uuHaXim",
            "Ky68Mom1cjCNJ84uniaZbGUPeD1GgJ3xcZnjjcn7qVB17VDcYtZW",
            "5JErFEK8PbUx83xiQxBmzcE19RvXjtSbMHwmaDdxUJFxJp3tX9x",
            "KzXY3qATuXwt1gmF92f3E4MaE5jusL8BBPaNRMcaEdkaCDoPnK3H",
            "5JZkHW39Mxx2b96wrrK8kjuEsYS8SuN7PHty4Fe4TCVuP6Q1hZC",
            "L4gYeVUQYN2PV8pQwLw9NRMNAxaZTWnpGm6xc32ypFoV1xhZoreW",
            "5KWMK1ZVSgevaZarNq1wTbyGfxe4GybPwmtCEq3G8zGyCCJoXS9",
        ]
    verify_wif_list(wifs)

if __name__ == "__main__":
    main()
