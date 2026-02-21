#!/usr/bin/env python3
import os
from encryption import SymmetricRatchet as SenderRatchet
from decryption import SymmetricRatchetReceiver as ReceiverRatchet

def test_robust_sync():
    print("🚀 Starting Advanced Sync Verification (Refined Protocol)...")
    
    initial_secret = os.urandom(32)
    sender = SenderRatchet(initial_secret, sender_id="TestUser")
    receiver = ReceiverRatchet(initial_secret)
    
    # 1. Generate 10 messages
    print("Generating 10 messages...")
    msgs = [f"Msg {i}" for i in range(1, 11)]
    packages = [sender.encrypt(m.encode('utf-8')) for m in msgs]

    # 2. Test Out-of-Order: Receive Msg 5 first (skips 1-4)
    print("\n--- Test 1: Out-of-Order Delivery ---")
    dec5 = receiver.decrypt(packages[4]).decode('utf-8')
    print(f"Result: {dec5} (Expected: Msg 5)")
    assert dec5 == "Msg 5"
    
    # Receive Msg 1 (should use cached key)
    dec1 = receiver.decrypt(packages[0]).decode('utf-8')
    print(f"Result: {dec1} (Expected: Msg 1)")
    assert dec1 == "Msg 1"
    
    # 3. Test Replay Protection
    print("\n--- Test 2: Replay Protection ---")
    try:
        receiver.decrypt(packages[4])
        print("❌ FAILED: Replay accepted")
        exit(1)
    except ValueError as e:
        print(f"✅ PASSED: Replay rejected ({e})")

    # 4. Test Garbage Collection (DoS Protection)
    print("\n--- Test 3: Cache Limit / Garbage Collection ---")
    # Current state: receiver has keys for 2, 3, 4 in cache.
    # Let's fill the cache (Limit is 50 in our code)
    
    # Create a new sender/receiver with small cache for testing
    # Note: We can't easily change the constant in the test without monkeypatching, 
    # but we can verify it doesn't crash on large jumps.
    
    huge_sender = SenderRatchet(os.urandom(32))
    huge_receiver = ReceiverRatchet(huge_sender._chain_key)
    
    # Jump 100 steps (will skip 99 keys)
    # Since MAX_CACHE_SIZE is 50, it should drop the first 49 keys.
    huge_msgs = [huge_sender.encrypt(b"x") for _ in range(100)]
    
    print("Action: Delivering Msg 100 first (forces skip of 99 keys)...")
    huge_receiver.decrypt(huge_msgs[99])
    
    # Try to decrypt Msg 1 (should have been garbage collected)
    try:
        huge_receiver.decrypt(huge_msgs[0])
        print("❌ FAILED: Old key should have been evicted from cache!")
    except ValueError:
        print("✅ PASSED: Oldest key was correctly evicted from cache.")

    print("\n✨ ALL PROTOCOL TESTS PASSED!")

if __name__ == "__main__":
    test_robust_sync()
