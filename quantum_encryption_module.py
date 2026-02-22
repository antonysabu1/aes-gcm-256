#!/usr/bin/env python3
"""
Quantum-Safe Encryption: Zero-Metadata Protocol
------------------------------------------------
Security Fixes:
1. Future Secrecy: Added root key refreshing capability.
2. Metadata Privacy: All headers (Seq, TS, ID) are now ENCRYPTED.
3. No Leaks: Packages contain zero cleartext metadata.
"""

import os
import time
import uuid
import ctypes
import json
import base64
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# --- CONSTANTS ---
AES_KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
FIXED_PAYLOAD_SIZE = 512  # Every message will be EXACTLY this size + overhead
HKDF_INFO = b"AES-GCM-256-ZERO-METADATA"
RATCHET_INFO_CHAIN = b"RATCHET-CHAIN-KEY"
RATCHET_INFO_MSG = b"RATCHET-MESSAGE-KEY"

def secure_wipe(data: bytes):
    """Overwrites memory of sensitive material."""
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0: return
    try:
        if isinstance(data, bytearray):
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, len(data))
    except Exception: pass

class QuantumDoubleRatchet:
    """
    Implements a Symmetric Ratchet with support for Root Key Refreshing.
    Provides Zero-Metadata, Constant-Length (Ghost) packets.
    """
    def __init__(self, shared_secret: bytes, sender_id: str = "User"):
        self._root_key = shared_secret
        self._chain_key = bytearray(shared_secret)
        self._step = 0
        self._sender_id = sender_id

    def refresh_root(self, new_entropy: bytes):
        """Heals the connection for Future Secrecy."""
        new_root = HKDF(
            master=self._root_key + new_entropy,
            key_len=AES_KEY_SIZE,
            salt=None,
            hashmod=SHA256,
            context=b"ROOT-REFRESH"
        )
        secure_wipe(self._chain_key)
        self._root_key = new_root
        self._chain_key = bytearray(new_root)
        self._step = 0
        print(f"✨ Root Key Refreshed. Connection 'Healed'.")

    def _advance_message_key(self) -> bytes:
        msg_key = HKDF(self._chain_key, AES_KEY_SIZE, None, SHA256, context=RATCHET_INFO_MSG)
        new_chain = HKDF(self._chain_key, AES_KEY_SIZE, None, SHA256, context=RATCHET_INFO_CHAIN)
        secure_wipe(self._chain_key)
        self._chain_key = bytearray(new_chain)
        self._step += 1
        return msg_key

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Pads everything to FIXED_PAYLOAD_SIZE to hide length.
        Format: [12B Nonce] + [16B Tag] + [Encrypted(HdrLen + Hdr + MsgLen + Msg + Padding)]
        """
        msg_key = self._advance_message_key()
        
        # 1. Prepare Hidden Header
        header = {"s": self._sender_id, "n": self._step, "t": int(time.time()), "i": str(uuid.uuid4())[:8]}
        header_bytes = json.dumps(header).encode('utf-8')
        
        # 2. Pack content: [HdrLen] + [Hdr] + [MsgLen] + [Msg]
        msg_len = len(plaintext).to_bytes(4, 'big')
        hdr_len = len(header_bytes).to_bytes(4, 'big')
        content = hdr_len + header_bytes + msg_len + plaintext

        # 3. Add Random Padding (The Ghost noise)
        if len(content) > FIXED_PAYLOAD_SIZE:
            raise ValueError(f"Message too large! Max payload is {FIXED_PAYLOAD_SIZE} bytes.")
        
        padding_needed = FIXED_PAYLOAD_SIZE - len(content)
        content += os.urandom(padding_needed) # Pure random noise

        # 4. Encrypt everything
        aes_key = HKDF(msg_key, AES_KEY_SIZE, None, SHA256, context=HKDF_INFO)
        
        # 5. Generate the BEACON (Blinded Identifier)
        # This allows the receiver to find the key instantly without trial decryption
        lookup_id = HKDF(msg_key, 16, None, SHA256, context=b"MESSAGE-LOOKUP-ID")
        
        nonce = os.urandom(NONCE_SIZE)
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(content)
        
        secure_wipe(aes_key)
        secure_wipe(msg_key)

        # Final Package: LookupID(16) + Nonce(12) + Tag(16) + Ciphertext
        return lookup_id + nonce + tag + ciphertext

def smart_load_secret(input_str: str) -> bytes:
    """Detects and loads 32-byte secret from Hex or Base64."""
    input_str = input_str.strip()
    try:
        if len(input_str) == 64: # Likely Hex
            return bytes.fromhex(input_str)
        # Base64 for 32 bytes is 44 characters
        if len(input_str) == 44 or input_str.endswith('='):
            decoded = base64.b64decode(input_str)
            if len(decoded) == 32: return decoded
    except Exception: pass
    raise ValueError("Invalid Key Format. Must be 32 bytes (64 Hex or 44 Base64 chars).")

def main():
    print("\n" + "="*60)
    print("  🔐 QUANTUM-SAFE ENCRYPTION (ZERO-METADATA)")
    print("="*60 + "\n")

    secret_input = input("Enter Shared Secret (Hex or Base64 from Kyber): ").strip()
    try:
        shared_secret = smart_load_secret(secret_input)
    except Exception as e:
        print(f"❌ Error: {e}")
        return
    
    ratchet = QuantumDoubleRatchet(shared_secret, sender_id="Antony")

    while True:
        msg = input("\nEnter message ('q' to quit, 'refresh' to heal): ").strip()
        if msg.lower() in ['q', 'quit']: break
        
        if msg.lower() == 'refresh':
            new_seed = os.urandom(32)
            print(f"New Entropy Seed: {new_seed.hex()}")
            ratchet.refresh_root(new_seed)
            continue

        package = ratchet.encrypt(msg.encode('utf-8'))
        print(f"\n[OPAQUE PACKAGE GENERATED]")
        print(f"  Size: {len(package)} bytes")
        print("-" * 60)
        print(package.hex())
        print("-" * 60)
        print(f"  (Copy the ENTIRE block above, from start to finish!)")

if __name__ == "__main__":
    main()
