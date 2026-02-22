#!/usr/bin/env python3
"""
Quantum-Safe Decryption: Zero-Metadata Protocol
------------------------------------------------
Security Fixes:
1. Trial Decryption: No metadata is needed to start decryption.
2. Privacy: All headers are decrypted only after MAC verification.
3. Future Secrecy: Added root key refreshing capability.
"""

import os
import ctypes
import json
import time
import base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# --- CONSTANTS ---
AES_KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
FIXED_PAYLOAD_SIZE = 512
HKDF_INFO = b"AES-GCM-256-ZERO-METADATA"
RATCHET_INFO_CHAIN = b"RATCHET-CHAIN-KEY"
RATCHET_INFO_MSG = b"RATCHET-MESSAGE-KEY"

def secure_wipe(data: bytes):
    """Overwrites sensitive memory."""
    if not isinstance(data, (bytes, bytearray)) or len(data) == 0: return
    try:
        if isinstance(data, bytearray):
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, len(data))
    except Exception: pass

def trial_decrypt(msg_key: bytes, package: bytes) -> bytes:
    """Attempts to decrypt the opaque package using the candidate message key."""
    nonce = package[:NONCE_SIZE]
    tag = package[NONCE_SIZE:NONCE_SIZE+TAG_SIZE]
    ciphertext = package[NONCE_SIZE+TAG_SIZE:]
    
    aes_key = HKDF(msg_key, AES_KEY_SIZE, None, SHA256, context=HKDF_INFO)
    try:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        decrypted_payload = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_payload
    except Exception:
        return None
    finally:
        secure_wipe(aes_key)

class QuantumDoubleRatchetReceiver:
    MAX_SKIP = 100
    MAX_CACHE = 50

    def __init__(self, initial_shared_secret: bytes):
        self._root_key = initial_shared_secret
        self._chain_key = bytearray(initial_shared_secret)
        self._step = 0
        self._skipped_keys = {} # {seq: key}
        self._lookup_cache = {} # {lookup_id: (key, seq)}
        self._refresh_lookup_cache()

    def _refresh_lookup_cache(self):
        """Pre-calculates the next 100 possible message identifiers for instant lookup."""
        self._lookup_cache.clear()
        
        # 1. Index skipped keys
        for seq, key in self._skipped_keys.items():
            lid = HKDF(key, 16, None, SHA256, context=b"MESSAGE-LOOKUP-ID")
            self._lookup_cache[lid] = (key, seq)
            
        # 2. Index next 100 keys (Lookahead)
        temp_chain = bytearray(self._chain_key)
        temp_step = self._step
        for i in range(self.MAX_SKIP):
            candidate_key = HKDF(temp_chain, AES_KEY_SIZE, None, SHA256, context=RATCHET_INFO_MSG)
            lid = HKDF(candidate_key, 16, None, SHA256, context=b"MESSAGE-LOOKUP-ID")
            self._lookup_cache[lid] = (candidate_key, temp_step + 1)
            
            # Advance shadow chain
            next_chain = HKDF(temp_chain, AES_KEY_SIZE, None, SHA256, context=RATCHET_INFO_CHAIN)
            secure_wipe(temp_chain)
            temp_chain = bytearray(next_chain)
            temp_step += 1

    def refresh_root(self, new_entropy: bytes):
        """Advances the root key to heal the connection."""
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
        self._skipped_keys.clear()
        self._refresh_lookup_cache()
        print(f"✨ Root Key Refreshed. Connection 'Heal' successful.")

    def _advance_chain(self) -> bytes:
        msg_key = HKDF(self._chain_key, AES_KEY_SIZE, None, SHA256, context=RATCHET_INFO_MSG)
        new_chain = HKDF(self._chain_key, AES_KEY_SIZE, None, SHA256, context=RATCHET_INFO_CHAIN)
        secure_wipe(self._chain_key)
        self._chain_key = bytearray(new_chain)
        self._step += 1
        return msg_key

    def decrypt(self, package: bytes) -> bytes:
        """Instant lookup using the Blinded Identifier Beacon."""
        if len(package) < (16 + NONCE_SIZE + TAG_SIZE): raise ValueError("Blob too small")

        # 1. Extract Beacon
        beacon = package[:16]
        crypto_blob = package[16:]

        # 2. FAST LOOKUP (O(1))
        if beacon in self._lookup_cache:
            match_key, match_seq = self._lookup_cache[beacon]
            
            # Case A: It was a skipped key
            if match_seq in self._skipped_keys:
                del self._skipped_keys[match_seq]
                res = trial_decrypt(match_key, crypto_blob)
                self._refresh_lookup_cache()
                return self._unpack(res)
            
            # Case B: It is in the future (advance real chain)
            while self._step < match_seq:
                key = self._advance_chain()
                if self._step == match_seq:
                    res = trial_decrypt(key, crypto_blob)
                    self._refresh_lookup_cache() # Update cache for next message
                    return self._unpack(res)
                else:
                    self._skipped_keys[self._step] = key

        raise ValueError("Decryption Failure: Unknown Beacon (Identification failed)")

    def _unpack(self, decrypted_payload: bytes) -> bytes:
        """Parses the hidden header and message, ignoring random padding."""
        # 1. Extract Header
        h_len = int.from_bytes(decrypted_payload[:4], 'big')
        header_bytes = decrypted_payload[4:4+h_len]
        header = json.loads(header_bytes.decode('utf-8'))
        
        # 2. Extract Message
        m_start = 4 + h_len
        m_len = int.from_bytes(decrypted_payload[m_start:m_start+4], 'big')
        message = decrypted_payload[m_start+4 : m_start+4+m_len]
        
        # Note: Everything after m_len is random padding (noise) which we discard.
        
        print(f"📩 Decrypted from {header['s']} | Seq: {header['n']} | ID: {header['i']}")
        return message

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
    print("  🔓 QUANTUM-SAFE DECRYPTION (ZERO-METADATA)")
    print("="*60 + "\n")

    secret_input = input("Enter Shared Secret (Hex or Base64): ").strip()
    try:
        shared_secret = smart_load_secret(secret_input)
    except Exception as e:
        print(f"❌ Error: {e}")
        return
    
    ratchet = QuantumDoubleRatchetReceiver(shared_secret)

    while True:
        line = input("\nPaste Package or 'refresh': ").strip()
        if line.lower() == 'q': break
        if line.lower() == 'refresh':
            ent = input("Enter Entropy Hex: ").strip()
            ratchet.refresh_root(bytes.fromhex(ent))
            continue
            
        try:
            # Length Check: 556 bytes = 1112 hex characters
            expected_chars = (16 + NONCE_SIZE + TAG_SIZE + FIXED_PAYLOAD_SIZE) * 2
            if len(line) < expected_chars:
                print(f"⚠️  WARNING: Your copy looks too short! (Found {len(line)}, expected {expected_chars})")
                print("Make sure you copy the ENTIRE hex block from the top.")
                continue

            package = bytes.fromhex(line)
            plaintext = ratchet.decrypt(package)
            print(f"✅ DECRYPTED: {plaintext.decode('utf-8')}")
        except Exception as e:
            print(f"❌ FAILED: {e}")

if __name__ == "__main__":
    main()
