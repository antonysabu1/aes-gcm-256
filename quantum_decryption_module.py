#!/usr/bin/env python3
"""
Quantum-Safe Symmetric Decryption Module (Standalone Version)
--------------------------------------------------------------
Features:
- AES-256-GCM Decryption
- HKDF Key Derivation with salt extraction
- Symmetric Ratchet (Receiver-side)
- Secure Memory Wipe (ctypes.memset)
- Integrated Interactive Testing

Target: Receiver-side (Decryption)
"""

import os
import ctypes
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

# --- CONSTANTS (Must match encryption module) ---
AES_KEY_SIZE = 32     # 256 bits
SALT_SIZE = 16        # 128 bits
NONCE_SIZE = 12       # 96 bits
TAG_SIZE = 16         # 128 bits
HKDF_INFO = b"AES-GCM-256-KEY"
RATCHET_INFO_CHAIN = b"RATCHET-CHAIN-KEY"
RATCHET_INFO_MSG = b"RATCHET-MESSAGE-KEY"

# --- CORE UTILITIES ---

def secure_wipe(data: bytes):
    """Overwrites the memory of a bytes object with zeros."""
    if not isinstance(data, (bytes, bytearray)):
        return
    buf_len = len(data)
    if buf_len == 0:
        return
    try:
        if isinstance(data, bytearray):
            ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data)), 0, buf_len)
        else:
            # We don't wipe immutable bytes to avoid corruption/segfaults
            pass
    except Exception:
        pass

# --- DECRYPTION LOGIC ---

def decrypt_message(
    shared_secret: bytes,
    package: bytes,
    aad: Optional[bytes] = None
) -> bytes:
    """
    Decrypt a message using AES-256-GCM with HKDF-derived key.
    
    Structure of package: salt (16) || nonce (12) || ciphertext (...) || tag (16)
    """
    if len(package) < (SALT_SIZE + NONCE_SIZE + TAG_SIZE):
        raise ValueError("Invalid package size")

    # 1. Extract components
    salt = package[:SALT_SIZE]
    nonce = package[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    ciphertext = package[SALT_SIZE+NONCE_SIZE:-TAG_SIZE]
    tag = package[-TAG_SIZE:]

    # 2. Derive the same AES key using the extracted salt
    aes_key = HKDF(
        master=shared_secret,
        key_len=AES_KEY_SIZE,
        salt=salt,
        hashmod=SHA256,
        context=HKDF_INFO
    )

    try:
        # 3. Initialize AES-256-GCM cipher for decryption
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        
        # 4. Add AAD (must match what was used during encryption)
        if aad is not None:
            cipher.update(aad)
        
        # 5. Decrypt and verify tag
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    finally:
        # 6. Securely wipe the derived key
        secure_wipe(aes_key)

# --- RATCHET (RECEIVER SIDE) ---

class SymmetricRatchetReceiver:
    """
    Implements a robust receiver-side symmetric key ratchet.
    Handles out-of-order messages and skipped messages using a key cache.
    """
    MAX_SKIP = 1000  # Prevent DOS attacks by limiting chain advancement

    def __init__(self, initial_shared_secret: bytes):
        self._chain_key = bytearray(initial_shared_secret)
        self._step = 0
        self._skipped_keys = {} # {seq: message_key}

    @property
    def step(self) -> int:
        return self._step

    def _advance_chain(self) -> bytes:
        """Internal: Advances the chain and returns the message key for current step."""
        message_key = HKDF(
            master=self._chain_key,
            key_len=AES_KEY_SIZE,
            salt=None,
            hashmod=SHA256,
            context=RATCHET_INFO_MSG
        )
        
        new_chain_key = HKDF(
            master=self._chain_key,
            key_len=AES_KEY_SIZE,
            salt=None,
            hashmod=SHA256,
            context=RATCHET_INFO_CHAIN
        )
        
        secure_wipe(self._chain_key)
        self._chain_key = bytearray(new_chain_key)
        self._step += 1
        return message_key

    def decrypt(self, package: bytes, aad: Optional[bytes] = None) -> bytes:
        """
        Decrypt message and advance the receiver ratchet.
        Now supports out-of-order messages using the prepended sequence number.
        """
        if len(package) < 4:
            raise ValueError("Package too small to contain sequence number")

        # 1. Extract sequence number
        seq_bytes = package[:4]
        msg_seq = int.from_bytes(seq_bytes, 'big')
        encrypted_data = package[4:]

        # 2. Build the appropriate AAD (must match sender's format)
        header_aad = seq_bytes
        if aad:
            header_aad += b"|" + aad

        # 3. Use cached key if available (out-of-order delivery)
        if msg_seq in self._skipped_keys:
            msg_key = self._skipped_keys.pop(msg_seq)
            try:
                plaintext = decrypt_message(msg_key, encrypted_data, aad=header_aad)
                return plaintext
            finally:
                secure_wipe(msg_key)

        # 4. Check if message is too old
        if msg_seq <= self._step:
            raise ValueError(f"Message expired or replayed (seq {msg_seq} <= current {self._step})")

        # 5. Catch up if sequence is ahead
        if msg_seq > self._step + self.MAX_SKIP:
            raise ValueError("Message sequence too far ahead (potential DOS)")

        # Advance chain until we hit the target sequence
        while self._step < msg_seq:
            msg_key = self._advance_chain()
            if self._step == msg_seq:
                # This is the key we need now
                try:
                    plaintext = decrypt_message(msg_key, encrypted_data, aad=header_aad)
                    return plaintext
                finally:
                    secure_wipe(msg_key)
            else:
                # Store this key for later (it was skipped)
                self._skipped_keys[self._step] = msg_key


# --- INTERACTIVE TESTING ---

def main():
    print("\n" + "="*60)
    print("  🔓 QUANTUM-SAFE DECRYPTION STANDALONE MODULE")
    print("  (Receiver-Side: Decryption Only)")
    print("="*60 + "\n")

    print("[SETUP] To decrypt, you need the EXACT initial shared secret.")
    secret_hex = input("Enter Shared Secret (Hex) or press Enter to use a test secret: ").strip()
    
    if not secret_hex:
        # For testing, we use a fixed secret that the user might have used in the other module
        shared_secret = b'\x00' * 32 
        print("Using default test secret (all zeros).")
    else:
        try:
            shared_secret = bytes.fromhex(secret_hex)
        except ValueError:
            print("Invalid Hex string. Exiting.")
            return

    ratchet = SymmetricRatchetReceiver(shared_secret)

    while True:
        print("-" * 60)
        package_hex = input("\nPaste Encrypted Package (Hex) to decrypt (or 'q' to quit): ").strip()

        if package_hex.lower() in ['q', 'quit', 'exit']:
            break

        if not package_hex:
            continue

        aad_str = input("Enter Metadata (AAD) used for this message (optional): ").strip()
        aad = aad_str.encode('utf-8') if aad_str else None

        try:
            package = bytes.fromhex(package_hex)
            # Decrypt using ratchet
            plaintext = ratchet.decrypt(package, aad=aad)
            
            print(f"\n✅ DECRYPTION SUCCESSFUL!")
            print(f"  Ratchet Step: {ratchet.step}")
            print(f"  Decrypted Message: {plaintext.decode('utf-8')}")
            
        except Exception as e:
            print(f"\n❌ DECRYPTION FAILED: {e}")
            print("  Check if the Hex, Secret, AAD, or Ratchet Step is correct.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExited by user.")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
