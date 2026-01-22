# Security Design Documentation
**Project:** Secure Multi-Client Communication Protocol  
**Course:** System and Network Security (CS5.470)  
**Lab:** Assignment 1

---

## 1. Overview
This document details the security architecture of the stateful, symmetric-key communication protocol designed to secure data transmission between a centralized analytics server and multiple distributed clients in a hostile network environment. The protocol ensures **Confidentiality**, **Integrity**, **Freshness**, and **Synchronization** without relying on public-key cryptography.

## 2. Threat Model
[cite_start]We assume an active network adversary capability defined as follows [cite: 41-47]:
* **Capabilities:** The attacker can capture, drop, reorder, replay, modify, and reflect packets.
* **Limitations:** The attacker cannot break AES-128 or HMAC-SHA256 cryptographic primitives.
* **Goal:** To compromise confidentiality, inject malicious data, desynchronize the session, or impersonate valid clients.

## 3. Cryptographic Primitives
[cite_start]The protocol is built upon standard, secure primitives allowed by the specification [cite: 55, 128-137]:
* **Encryption:** AES-128 in CBC mode with manual PKCS#7 padding.
* **Integrity & Authentication:** HMAC-SHA256.
* **Key Derivation/Evolution:** SHA-256 (for ratcheting).
* **Randomness:** OS-level secure random number generation (for IVs).

## 4. Security Mechanisms & Defenses

### 4.1. Confidentiality & Encryption
* **Mechanism:** All payloads are encrypted using AES-128-CBC.
* [cite_start]**Defense:** A fresh random 16-byte IV is generated for every message[cite: 63]. This ensures that identical plaintexts result in distinct ciphertexts, preventing traffic analysis based on pattern matching.

### 4.2. Integrity & Authenticity (Encrypt-then-MAC)
* **Mechanism:** An HMAC-SHA256 tag is computed over the `Header || [cite_start]Ciphertext`[cite: 66].
* **Defense:**
    * **Tampering:** Any modification to the ciphertext, IV, or header fields (Opcode, Round ID) invalidates the HMAC. [cite_start]The receiver verifies the HMAC *before* attempting decryption[cite: 70].
    * **Padding Oracle Attacks:** Since decryption and unpadding only occur *after* a successful HMAC verification, the system is immune to padding oracle attacks (Vaudenay's attack).

### 4.3. Replay Attack Resistance
* [cite_start]**Mechanism:** The protocol maintains a strictly monotonic `Round` counter in the state of both Client and Server[cite: 20]. The Round ID is included in the message header.
* **Defense:** If an attacker captures a valid packet from Round $R$ and replays it later, the receiver (now at Round $R+1$) compares the packet's `Round ID` (0) with its expected state ($1$). [cite_start]The mismatch causes a `ProtocolError` and immediate session termination[cite: 24, 27].

### 4.4. Forward Secrecy (Key Ratcheting)
* [cite_start]**Mechanism:** Session keys are evolved (ratcheted) after every valid message exchange using a one-way hash function (SHA-256) [cite: 101-105].
    * $Key_{R+1} = SHA256(Key_R || Context)$
* **Defense:** If the current session key is compromised, the attacker cannot use it to decrypt *past* messages because the keys for previous rounds cannot be derived backwards (due to the pre-image resistance of SHA-256).

### 4.5. Reflection Attack Resistance
* [cite_start]**Mechanism:** The protocol uses distinct key sets for each direction [cite: 85-98]:
    * `C2S_Mac` (Client-to-Server)
    * `S2C_Mac` (Server-to-Client)
* **Defense:** If an attacker intercepts a packet sent by the Server (signed with `S2C_Mac`) and reflects it back to the Server, the Server will attempt to verify it using `C2S_Mac`. The verification will fail.

## 5. Vulnerability Analysis (Attack Scenarios)

The following table details the protocol's response to the specific attacks simulated in `attacks.py`.

| ID | Attack Scenario | Defense Mechanism | Outcome |
| :--- | :--- | :--- | :--- |
| **1** | **Replay Attack** | Receiver compares Header `Round` vs. Internal State `Round`. | **Dropped** (Round Mismatch) |
| **2** | **Integrity (Bit-Flipping)** | HMAC-SHA256 verification over `Header || Ciphertext`. | **Dropped** (HMAC Invalid) |
| **3** | **Desynchronization (Drop)** | Receiver detects gap in Round numbers (e.g., receives R=2 when expecting R=1). | **Dropped** (Round Mismatch) |
| **4** | **Reflection Attack** | Distinct MAC keys for `C2S` and `S2C` directions. | **Dropped** (HMAC Invalid) |
| **5** | **Phase Violation** | [cite_start]FSM checks `Opcode` validity against current `Phase` (INIT vs ACTIVE)[cite: 25]. | **Dropped** (Invalid Opcode) |
| **6** | **Client Impersonation** | Initial keys derived from unique, pre-shared Master Keys ($K_i$). | **Dropped** (HMAC Invalid) |
| **7** | **Truncation Attack** | Fixed header length checks and HMAC verification of complete packet. | **Dropped** (Length/HMAC Error) |
| **8** | **Invalid Direction Flag** | [cite_start]Explicit check `if direction != expected_direction` in parser[cite: 69]. | **Dropped** (Metadata Mismatch) |
| **9** | **Padding Manipulation** | Encrypt-then-MAC construction; HMAC checked *before* unpadding. | **Dropped** (HMAC Invalid) |
| **10**| **Wrong Client ID** | Explicit check `if header_client_id != session_client_id`. | **Dropped** (ID Mismatch) |

## 6. Conclusion
The implemented protocol successfully meets the assignment objectives by enforcing a strict state machine, utilizing robust authenticated encryption (Encrypt-then-MAC), and implementing key evolution. The analysis confirms resilience against the defined threat model, ensuring that any active interference results in a safe termination of the compromised session.
