
# Secure Multi-Client Communication Protocol (SNS Lab 1)

**Course:** System and Network Security (CS5.470)  
**Assignment:** Lab 1: Secure Multi-Client Communication with Symmetric Keys  
**Language:** Python 3  
**Submission Deadline:** 22-01-2026

---

## 📌 Overview
This project implements a **stateful, symmetric-key secure communication protocol** between a centralized analytics server and multiple distributed clients. The system is designed to operate in a hostile network environment where an active adversary can capture, drop, reorder, replay, modify, or reflect packets.

### Key Capabilities
- **Confidentiality:** AES-128-CBC encryption with manual PKCS#7 padding.
- **Integrity & Authentication:** HMAC-SHA256 using an Encrypt-then-MAC construction.
- **Stateful Security:** Strict state machine enforcement (INIT → ACTIVE → TERMINATED).
- **Forward Secrecy:** Per-message key ratcheting (evolution) using SHA-256 hash chains.
- **Replay Resistance:** Monotonic round counters enforced by the receiver.
- **Dynamic Aggregation:** The server handles multiple clients concurrently and aggregates data when rounds synchronize.

---

## 📂 File Structure

| File | Description |
| :--- | :--- |
| `server.py` | Multi-threaded server that handles dynamic client connections, performs state-based aggregation, and broadcasts results. |
| `client.py` | Client simulation that performs the handshake, sends data rounds, and handles key evolution. |
| `protocol_fsm.py` | **Core Logic:** Implements the Protocol Finite State Machine, packet parsing, key ratcheting, and validation logic. |
| `crypto_utils.py` | Wrappers for cryptographic primitives (AES, HMAC, Padding) using `pycryptodome`. |
| `attacks.py` | Test suite containing 10 specific attack scenarios to demonstrate protocol security. |
| `SECURITY.md` | Detailed security analysis, threat model, and defense mechanisms. |
| `test.py` | Unit tests for cryptographic primitives (padding, encryption, HMAC). |

---

## ⚙️ Prerequisites
This project requires **Python 3.x** and the `pycryptodome` library for raw AES primitives.

```bash
pip install pycryptodome
```

> Note: The use of high-level authenticated encryption libraries (like `cryptography.fernet` or AES-GCM) is strictly forbidden and intentionally not used in this project.

---

## 🚀 Execution Guide

1. Start the Server

The server listens for incoming connections and creates a new thread for each client.

```bash
python server.py
```

2. Start Clients

Run clients in separate terminal windows. The client script takes a `client_id` (e.g., 1 or 2) as an argument.

Terminal 2 (Client 1):
```bash
python client.py 1
```

Terminal 3 (Client 2):
```bash
python client.py 2
```

Observation: As clients send data, the server aggregates values from peers synchronized to the same round and returns the sum. Late-joining clients will be processed independently without blocking existing sessions.

3. Run Security Attacks

The `attacks.py` script simulates a malicious adversary attempting various exploits against the server. Ensure `server.py` is running before executing.

```bash
python attacks.py
```

---

## ⚔️ Implemented Attack Scenarios

`attacks.py` automatically verifies the following threats (expected outcome shown):

- Replay Attack: Re-transmits a valid, previously captured packet. — Dropped (Round Mismatch)
- Integrity Attack: Flips bits in the ciphertext to corrupt the payload. — Dropped (HMAC failure)
- Desynchronization (Drop): Skips a message to create a gap in round numbers. — Dropped (Round Mismatch)
- Reflection Attack: Reflects a Server-to-Client packet back to the Server. — Dropped (HMAC/Key Direction mismatch)
- Phase Violation: Sends CLIENT_DATA before completing the Handshake. — Dropped (Invalid Opcode)
- Client Impersonation: Signs a packet claiming to be Client 2 using Client 1's key. — Dropped (HMAC failure)
- Truncation Attack: Sends a packet with incomplete HMAC/Header. — Dropped (Length/HMAC error)
- Invalid Direction Flag: Sends a packet with the wrong direction bit set. — Dropped (Metadata validation)
- Padding Manipulation: Modifies ciphertext to trigger padding errors. — Dropped (HMAC check before unpadding)
- Wrong Client ID: Sends a packet where the Header ID matches a different session. — Dropped (ID mismatch)

---

## 📝 Protocol Specifications

### Message Format

Each message follows this byte-level structure:

| Opcode (1) | ClientID (1) | Round (4) | Direction (1) | IV (16) | Ciphertext (Var) | HMAC (32) |

### Key Evolution (Ratcheting)

Keys are updated only after a successful message exchange in the ACTIVE phase.

Examples (informal):

```
C2S_Enc_{R+1} = SHA256(C2S_Enc_R || Ciphertext_R)
C2S_Mac_{R+1} = SHA256(C2S_Mac_R || IV_R)
S2C_Enc_{R+1} = SHA256(S2C_Enc_R || AggregatedData_R)
S2C_Mac_{R+1} = SHA256(S2C_Mac_R || StatusCode_R)
```

---

