# 🔐 Quantum-Safe Zero-Metadata Protocol (AES-GCM-256)

A high-performance, stealth-oriented symmetric encryption prototype featuring a **Symmetric Ratchet** core and **Traffic Analysis Defense**. This project implements a "Zero-Metadata" architecture, ensuring that not only the message content but also the conversation metadata remains completely opaque to observers.

---

## 🛡️ Key Security Features

### 1. Zero-Metadata Architecture
Unlike standard encryption which leaves headers (sender ID, sequence numbers) in cleartext, this protocol encrypts the entire header object. To an observer, the package is a 100% opaque blob with zero identifying information.

### 2. Ghost Padding (Traffic Analysis Defense)
To prevent "Length Leakage," every message is padded with random noise to reach a fixed size.
- **Fixed Payload**: 512 bytes.
- **Total Packet Size**: 540 bytes (Beacon + Nonce + Tag + Payload).
- **Benefit**: An attacker cannot tell if you sent a "Yes" or a 500-word essay. Your communication patterns remain secret.

### 3. Future Secrecy (Root Key Healing)
Includes a `refresh` mechanism that allows users to introduce new entropy into the Root Key. 
- **Effect**: If a current key is compromised, performing a refresh "heals" the connection and locks out the attacker from all future communication.

### 4. Blinded Identifiers (Beacon Lookup)
Uses a one-way hashed "Beacon" at the start of every package.
- **O(1) Performance**: The receiver identifies the correct key instantly via a fast-lookup dictionary.
- **Privacy**: The beacon ratchets with every message, making it impossible for outsiders to track or link separate messages to the same user.

### 5. Forward Secrecy
Implemented via a Symmetric Ratchet. Every message uses a unique key derived from the previous state. Once a message is decrypted, the key is securely wiped from memory, ensuring past messages cannot be decrypted even if the current state is stolen.

---

## 🛠️ Cryptographic Specifications
- **Cipher**: AES-256-GCM (Galois/Counter Mode)
- **KDF**: HKDF (HMAC-based Key Derivation Function) with SHA-256
- **Key Size**: 256-bit (32 bytes)
- **Tag Size**: 128-bit (16 bytes)
- **Memory Security**: Manual memory overwriting (`ctypes.memset`) for sensitive key material.

---

## 🚀 Quick Start

### Requirements
- Python 3.x
- `pycryptodome` library

### Installation
```bash
pip install pycryptodome
```

### Usage
1. **The Sender**: Run `encryption.py`. Copy the generated **Shared Secret**.
   ```bash
   python3 encryption.py
   ```
2. **The Receiver**: Run `decryption.py` and paste the Shared Secret.
   ```bash
   python3 decryption.py
   ```
3. **Communication**:
   - Type a message in the encryption window.
   - Copy the **entire** hex block (ensure you grab the whole string!).
   - Paste it into the decryption window.

4. **Healing the Connection**:
   - Type `refresh` in the encryption window to generate a new entropy seed.
   - Type `refresh` in the decryption window and provide that seed.

---

## ⚠️ Security Limitations (Project Status)
This is a **cryptographic prototype**. While the math is solid, please note:
- **State Persistence**: Keys live in RAM. Closing the script resets the ratchet.
- **Key Exchange**: This prototype assumes you have already shared the "Shared Secret" securely. In a production environment, this should be handled via **Kyber-768** or **ECDH**.
- **Language**: Python's garbage collection may leave temporary traces of keys in memory; for absolute memory safety, a systems language like Rust is recommended.

---
*Created as part of a Mini-Project on Advanced Agentic Coding and Quantum-Safe Messaging.*
