#!/usr/bin/env python3
import os
from quantum_encryption_module import SymmetricRatchet as SenderRatchet
from quantum_decryption_module import SymmetricRatchetReceiver as ReceiverRatchet

def test_robust_sync():
    print("🚀 Starting Advanced Sync Verification (Out-of-Order Testing)...")
    
    initial_secret = os.urandom(32)
    sender = SenderRatchet(initial_secret)
    receiver = ReceiverRatchet(initial_secret)
    
    # 1. Generate 5 messages
    print("Generating 5 messages...")
    msgs = ["Msg 1", "Msg 2", "Msg 3", "Msg 4", "Msg 5"]
    packages = []
    for m in msgs:
        packages.append(sender.encrypt(m.encode('utf-8')))

    # 2. Test Out-of-Order: Receive Msg 3, then Msg 1, then Msg 2
    print("\n--- Test 1: Out-of-Order Delivery ---")
    
    # Receive Msg 3 (this skips 1 and 2)
    print("Action: Delivering Msg 3 first...")
    dec3 = receiver.decrypt(packages[2]).decode('utf-8')
    print(f"Result: {dec3} (Expected: Msg 3)")
    assert dec3 == "Msg 3"
    
    # Receive Msg 1 (should use cached key)
    print("Action: Delivering Msg 1...")
    dec1 = receiver.decrypt(packages[0]).decode('utf-8')
    print(f"Result: {dec1} (Expected: Msg 1)")
    assert dec1 == "Msg 1"
    
    # Receive Msg 2 (should use cached key)
    print("Action: Delivering Msg 2...")
    dec2 = receiver.decrypt(packages[1]).decode('utf-8')
    print(f"Result: {dec2} (Expected: Msg 2)")
    assert dec2 == "Msg 2"

    # 3. Test Continuous: Receive Msg 4, then Msg 5
    print("\n--- Test 2: Resume Normal Flow ---")
    dec4 = receiver.decrypt(packages[3]).decode('utf-8')
    print(f"Result: {dec4} (Expected: Msg 4)")
    assert dec4 == "Msg 4"
    
    dec5 = receiver.decrypt(packages[4]).decode('utf-8')
    print(f"Result: {dec5} (Expected: Msg 5)")
    assert dec5 == "Msg 5"

    # 4. Test Replay Attack
    print("\n--- Test 3: Replay Protection ---")
    try:
        print("Action: Replaying Msg 3...")
        receiver.decrypt(packages[2])
        print("❌ FAILED: Replay was accepted!")
    except ValueError as e:
        print(f"✅ PASSED: Replay rejected as expected ({e})")

    # 5. Test Huge Skip (DOS Protection)
    print("\n--- Test 4: DOS Protection (Huge Skip) ---")
    huge_sender = SenderRatchet(os.urandom(32))
    huge_receiver = ReceiverRatchet(huge_sender._chain_key) # Same key
    # Manually tampering with sender to jump 2000 steps
    huge_sender._step = 2000
    huge_pkg = huge_sender.encrypt(b"Danger")
    try:
        huge_receiver.decrypt(huge_pkg)
        print("❌ FAILED: Huge skip was accepted!")
    except ValueError as e:
        print(f"✅ PASSED: Huge skip rejected ({e})")

    print("\n✨ ALL ROBUSTNESS TESTS PASSED!")

if __name__ == "__main__":
    test_robust_sync()
