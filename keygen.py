#!/usr/bin/env python3
"""
iApp License Key Generator

Developer-side tool for generating license keys.
Keep this script PRIVATE - do NOT include in distributed app.

Algorithm:
    key = HMAC-SHA256(secret, identifier)
    formatted as XXXX-XXXX-XXXX-XXXX

Usage:
    python keygen.py                        # Generate 1 random key
    python keygen.py -n 10                  # Batch generate 10 keys
    python keygen.py -i "QQ:123456"         # Generate key for specific user
    python keygen.py -v ABCD-EF12-3456-7890 # Verify a key
"""

import hmac
import hashlib
import secrets
import argparse
import json
import os
import time
from datetime import datetime
from pathlib import Path

# ============================================================
# IMPORTANT: Change this to your own secret. Keep it PRIVATE.
# This is the master secret for key generation.
# ============================================================
SECRET = "iApp_LingLuo_2026_SecretKey_ChangeMe"

DB_FILE = Path(__file__).parent / "keys.json"


def _hmac_hash(data: str) -> str:
    """Generate HMAC-SHA256 hash"""
    h = hmac.new(SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()
    return h


def generate_key(identifier: str = None) -> tuple[str, str]:
    """
    Generate a license key.
    
    Returns:
        (formatted_key, identifier)
    """
    if identifier is None:
        identifier = f"rand_{secrets.token_hex(8)}_{int(time.time())}"
    
    raw = _hmac_hash(identifier)
    
    # Take 16 hex chars and format as XXXX-XXXX-XXXX-XXXX (uppercase)
    short = raw[:16].upper()
    key = "-".join([short[i:i+4] for i in range(0, 16, 4)])
    
    return key, identifier


def get_key_hash(key: str) -> str:
    """
    Hash a key for verification.
    This hash is what goes into the app's verification list.
    """
    clean = key.replace("-", "").strip().upper()
    return hashlib.sha256(clean.encode()).hexdigest()


def verify_key(key: str) -> bool:
    """Verify a key against the database"""
    db = load_db()
    key_hash = get_key_hash(key)
    
    for entry in db.get("keys", []):
        if entry["hash"] == key_hash:
            return True
    return False


def load_db() -> dict:
    """Load key database"""
    if DB_FILE.exists():
        return json.loads(DB_FILE.read_text(encoding="utf-8"))
    return {"keys": [], "hashes": []}


def save_db(db: dict):
    """Save key database"""
    DB_FILE.write_text(json.dumps(db, indent=2, ensure_ascii=False), encoding="utf-8")


def add_key_to_db(key: str, identifier: str):
    """Add a key to the database"""
    db = load_db()
    key_hash = get_key_hash(key)
    
    entry = {
        "key": key,
        "hash": key_hash,
        "identifier": identifier,
        "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "used": False
    }
    db["keys"].append(entry)
    
    # Also maintain a pure hash list for easy export to JS
    if key_hash not in db.get("hashes", []):
        db.setdefault("hashes", []).append(key_hash)
    
    save_db(db)


def export_hashes() -> list[str]:
    """Export all key hashes for embedding in the verification page"""
    db = load_db()
    return db.get("hashes", [])


def main():
    parser = argparse.ArgumentParser(
        description="iApp License Key Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("-n", "--count", type=int, default=1,
                        help="Number of keys to generate (default: 1)")
    parser.add_argument("-i", "--identifier", type=str, default=None,
                        help="User identifier (e.g. QQ number)")
    parser.add_argument("-v", "--verify", type=str, default=None,
                        help="Verify a key")
    parser.add_argument("--export", action="store_true",
                        help="Export key hashes as JS array")
    parser.add_argument("--list", action="store_true",
                        help="List all generated keys")
    
    args = parser.parse_args()
    
    if args.verify:
        key_hash = get_key_hash(args.verify)
        valid = verify_key(args.verify)
        status = "VALID" if valid else "NOT FOUND"
        print(f"Key:    {args.verify}")
        print(f"Hash:   {key_hash}")
        print(f"Status: {status}")
        return
    
    if args.export:
        hashes = export_hashes()
        print("// Paste this into verify.html")
        print(f"const VALID_HASHES = {json.dumps(hashes, indent=2)};")
        return
    
    if args.list:
        db = load_db()
        keys = db.get("keys", [])
        if not keys:
            print("No keys generated yet.")
            return
        print(f"Total: {len(keys)} keys\n")
        print(f"{'Key':<24} {'Identifier':<30} {'Created':<20} {'Used'}")
        print("-" * 100)
        for entry in keys:
            print(f"{entry['key']:<24} {entry['identifier']:<30} {entry['created']:<20} {entry.get('used', False)}")
        return
    
    # Generate keys
    print(f"Generating {args.count} key(s)...\n")
    
    for i in range(args.count):
        ident = args.identifier if args.identifier else None
        if args.identifier and args.count > 1:
            ident = f"{args.identifier}_{i+1}"
        
        key, identifier = generate_key(ident)
        add_key_to_db(key, identifier)
        print(f"  Key:  {key}")
        print(f"  Hash: {get_key_hash(key)}")
        if i < args.count - 1:
            print()
    
    print(f"\nSaved to {DB_FILE}")
    print(f"\nTip: Run 'python keygen.py --export' to get hashes for the verification page.")


if __name__ == "__main__":
    main()
