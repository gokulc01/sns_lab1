# Secure Multi-Client Communication Protocol (SNS Lab 1)

**Course:** System and Network Security (CS5.470)  
**Assignment:** Lab 1: Secure Multi-Client Communication with Symmetric Keys  
**Language:** Python 3  

---

## 📌 Overview
This project implements a **stateful, symmetric-key secure communication protocol** between a centralized analytics server and multiple clients. It is designed to operate in a hostile network environment where an active adversary can replay, modify, or reflect packets.

### Key Features
* **Confidentiality:** AES-128-CBC encryption with manual PKCS#7 padding.
* **Integrity & Authentication:** HMAC-SHA256 (Encrypt-then-MAC).
* **Stateful Security:** Strict state machine enforcement (INIT $\to$ ACTIVE $\to$ TERMINATED).
* **Forward Secrecy:** Per-message key ratcheting (evolution) using SHA-256 hash chains.
* **Replay Resistance:** Monotonic round counters to prevent packet replay.
* **Multi-Client Aggregation:** Server aggregates data from multiple clients before responding.

---

## 📂 File Structure

| File | Description |
| :--- | :--- |
| `server.py` | Centralized server that handles multiple clients, aggregates data, and broadcasts results. |
| `client.py` | Client simulation that performs the handshake, sends data, and handles key evolution. |
| `protocol_fsm.py` | **Core Logic:** Implements the Protocol Finite State Machine, packet parsing, and key ratcheting. |
| `crypto_utils.py` | Cryptographic primitives (AES, HMAC, Padding) using `pycryptodome`. |
| `attacks.py` | Suite of 10 different attack scenarios to test protocol security. |
| `SECURITY.md` | Detailed security analysis, threat model, and defense mechanisms. |
| `README.md` | Project documentation and usage guide. |

---

## ⚙️ Prerequisites
This project requires **Python 3.x** and the `pycryptodome` library for raw AES primitives.

```bash
pip install pycryptodome
