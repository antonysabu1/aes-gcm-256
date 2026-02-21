#!/usr/bin/env python3
import os
from quantum_encryption_module import SymmetricRatchet as SenderRatchet
from quantum_decryption_module import SymmetricRatchetReceiver as ReceiverRatchet

def test_sync():
    print("🚀 Starting Sync Verification Test...")
    
    # Unified initial secret
    initial_secret = os.urandom(32)
    print(f"Initial Secret (Hex): {initial_secret.hex()}\n")
    
    sender = SenderRatchet(initial_secret)
    receiver = ReceiverRatchet(initial_secret)
    
    messages = [
        "Hello from the quantum world!",
        "This is the second message in the chain.",
        "Forward secrecy test message."
    ]
    
    for i, msg in enumerate(messages):
        print(f"--- Message {i+1} ---")
        plaintext = msg.encode('utf-8')
        aad = f"seq:{i+1}".encode('utf-8')
        
        # 1. Encrypt
        package = sender.encrypt(plaintext, aad=aad)
        print(f"Encrypted Package: {package.hex()[:32]}...")
        
        # 2. Decrypt
        decrypted = receiver.decrypt(package, aad=aad)
        print(f"Decrypted Result:  {decrypted.decode('utf-8')}")
        
        assert decrypted == plaintext
        print("✅ Message match confirmed.\n")
        
    print("✨ ALL TESTS PASSED: Sender and Receiver ratchets are perfectly in sync.")

if __name__ == "__main__":
    try:
        test_sync()
    except Exception as e:
        print(f"❌ TEST FAILED: {e}")
