import socket
import time
import struct
import os
from protocol_fsm import (
    ProtocolSession,
    DIR_C2S,
    DIR_S2C,
    CLIENT_HELLO,
    SERVER_CHALLENGE,
    CLIENT_DATA,
    TERMINATE,
    KEY_DESYNC_ERROR,
    SERVER_AGGR_RESPONSE,
)

HOST = "127.0.0.1"
PORT = 65432
MASTER_KEY = b"masterkey_client1_32bytes_long_!!"
CLIENT_ID = 1


def perform_handshake(s, session):
    """Helper to get session into ACTIVE state"""
    hello = session.build_message(CLIENT_HELLO, b"HELLO", DIR_C2S)
    s.sendall(hello)
    data = s.recv(4096)
    if not data:
        raise Exception("Connection closed during handshake")
    opcode, _ = session.parse_message(data, DIR_S2C)
    if opcode == SERVER_CHALLENGE:
        print(f"[ATTACKER] Handshake Complete. Session is ACTIVE.")


def check_result(s, attack_name):
    try:
        response = s.recv(4096)
        if not response:
            print(f"[RESULT] ✅ SUCCESS: Server terminated connection ({attack_name}).")
        else:
            print(
                f"[RESULT] ❌ FAILURE: Server accepted malicious packet ({attack_name})."
            )
    except ConnectionResetError:
        print(f"[RESULT] ✅ SUCCESS: Server reset connection ({attack_name}).")


# --- 1. Replay Attack ---
def run_replay_attack():
    print("\n--- ⚔️  SCENARIO 1: REPLAY ATTACK ⚔️  ---")
    session = ProtocolSession(CLIENT_ID, MASTER_KEY, "client")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            perform_handshake(s, session)

            # Send valid packet
            valid_msg = session.build_message(CLIENT_DATA, b"100", DIR_C2S)
            s.sendall(valid_msg)
            time.sleep(0.2)

            print(f"[ATTACKER] 🛑 REPLAYING the same Data packet...")
            s.sendall(valid_msg)  # Replay
            check_result(s, "Replay")
    except Exception as e:
        print(f"[ERROR] {e}")


# --- 2. Integrity (Bit-Flipping) ---
def run_integrity_attack():
    print("\n--- ⚔️  SCENARIO 2: INTEGRITY (TAMPERING) ATTACK ⚔️  ---")
    session = ProtocolSession(CLIENT_ID, MASTER_KEY, "client")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            perform_handshake(s, session)

            msg_list = bytearray(session.build_message(CLIENT_DATA, b"100", DIR_C2S))
            print("[ATTACKER] Flipping bits in ciphertext...")
            msg_list[30] ^= 0xFF
            s.sendall(bytes(msg_list))
            check_result(s, "HMAC/Integrity")
    except Exception as e:
        print(f"[ERROR] {e}")


# --- 3. Desynchronization (Drop) ---
def run_desync_attack():
    print("\n--- ⚔️  SCENARIO 3: DESYNCHRONIZATION (MESSAGE DROP) ⚔️  ---")
    session = ProtocolSession(CLIENT_ID, MASTER_KEY, "client")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            perform_handshake(s, session)

            print("[ATTACKER] Generating Round 0 packet... (and DROPPING it)")
            _ = session.build_message(CLIENT_DATA, b"100", DIR_C2S)

            print(
                f"[ATTACKER] Sending Round {session.round} packet (Server expects Round {session.round - 1})..."
            )
            round_1_msg = session.build_message(CLIENT_DATA, b"200", DIR_C2S)
            s.sendall(round_1_msg)
            check_result(s, "Round Mismatch")
    except Exception as e:
        print(f"[ERROR] {e}")


# --- 4. Reflection Attack ---
def run_reflection_attack():
    print("\n--- ⚔️  SCENARIO 4: REFLECTION ATTACK ⚔️  ---")
    session = ProtocolSession(CLIENT_ID, MASTER_KEY, "client")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            # Send HELLO
            hello = session.build_message(CLIENT_HELLO, b"HELLO", DIR_C2S)
            s.sendall(hello)

            # Receive CHALLENGE
            challenge_packet = s.recv(4096)

            print("[ATTACKER] 🪞 REFLECTING the Challenge packet back to Server...")
            s.sendall(challenge_packet)
            check_result(s, "Reflection/Key Direction")
    except Exception as e:
        print(f"[ERROR] {e}")


# --- 5. Phase Violation (Invalid Opcode) ---
def run_phase_violation_attack():
    print("\n--- ⚔️  SCENARIO 5: PHASE VIOLATION (INVALID OPCODE) ⚔️  ---")
    session = ProtocolSession(CLIENT_ID, MASTER_KEY, "client")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            # DO NOT Handshake. Directly send CLIENT_DATA in INIT phase.

            print("[ATTACKER] Sending CLIENT_DATA while in INIT phase...")
            # We force build a DATA message manually even though FSM is in INIT
            # We must trick build_message or construct manually.
            # ProtocolSession.build_message allows opcodes, but server checks state.
            msg = session.build_message(CLIENT_DATA, b"100", DIR_C2S)
            s.sendall(msg)
            check_result(s, "Phase Violation")
    except Exception as e:
        print(f"[ERROR] {e}")


# --- 6. Client Impersonation ---
def run_impersonation_attack():
    print("\n--- ⚔️  SCENARIO 6: CLIENT IMPERSONATION ⚔️  ---")
    # Attacker tries to be Client 2 but uses Client 1's Master Key
    session = ProtocolSession(2, MASTER_KEY, "client")  # ID=2, Key=Client1's
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))

            print(
                "[ATTACKER] Sending HELLO claiming to be Client 2 (signed with Client 1 key)..."
            )
            hello = session.build_message(CLIENT_HELLO, b"HELLO", DIR_C2S)
            s.sendall(hello)
            check_result(s, "Impersonation/Auth Failure")
            # Server derives keys for Client 2 using Client 2's master key.
            # Attacker signed with Client 1's derived keys. HMAC will mismatch.
    except Exception as e:
        print(f"[ERROR] {e}")


# --- 7. Truncation Attack ---
def run_truncation_attack():
    print("\n--- ⚔️  SCENARIO 7: TRUNCATION ATTACK ⚔️  ---")
    session = ProtocolSession(CLIENT_ID, MASTER_KEY, "client")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            perform_handshake(s, session)

            msg = session.build_message(CLIENT_DATA, b"100", DIR_C2S)
            # Cut off the last byte of HMAC
            truncated = msg[:-1]
            print("[ATTACKER] Sending Truncated Packet (Length mismatch)...")
            s.sendall(truncated)
            # The server might hang waiting for more bytes or reject it.
            # To test reaction, we close write side or send garbage after.
            # Usually, our server checks 'if len(raw) < 23+32'.
            # If we send enough for header but cut HMAC:
            check_result(s, "Truncation")
    except Exception as e:
        print(f"[ERROR] {e}")


# --- 8. Invalid Direction Flag ---
def run_direction_flag_attack():
    print("\n--- ⚔️  SCENARIO 8: INVALID DIRECTION FLAG ⚔️  ---")
    session = ProtocolSession(CLIENT_ID, MASTER_KEY, "client")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            perform_handshake(s, session)

            # Build valid message but force Direction to be DIR_S2C (2)
            # The server expects DIR_C2S (1)
            print("[ATTACKER] Sending Packet with Direction=SERVER_TO_CLIENT...")
            # We have to hack build_message or struct pack manually
            # Let's manually construct header for valid ciphertext
            iv = os.urandom(16)
            # Opcode 30, ID 1, Round 0, Dir 2 (Wrong!)
            header = struct.pack("!BBIB", 30, 1, 0, 2) + iv

            # We need valid HMAC for this header+cipher to prove the checking order
            # If we sign it correctly, server rejects on Direction check.
            from protocol_fsm import sha256, hmac_sha256, pkcs7_pad, aes_cbc_encrypt

            # Encrypt payload
            key = session._aes_key(session.C2S_Enc)
            padded = pkcs7_pad(b"100")
            ciphertext = aes_cbc_encrypt(key, iv, padded)

            # Sign it with Client Key (so HMAC is valid mathematically)
            hmac_val = hmac_sha256(session.C2S_Mac, header + ciphertext)

            packet = header + ciphertext + hmac_val
            s.sendall(packet)
            check_result(s, "Direction Mismatch")
    except Exception as e:
        print(f"[ERROR] {e}")


# --- 9. Ciphertext-Only Modification (Padding Oracle Probe) ---
def run_padding_manipulation():
    print("\n--- ⚔️  SCENARIO 9: PADDING MANIPULATION ⚔️  ---")
    session = ProtocolSession(CLIENT_ID, MASTER_KEY, "client")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            perform_handshake(s, session)

            # 1. Get valid encrypted packet
            msg_list = bytearray(session.build_message(CLIENT_DATA, b"100", DIR_C2S))

            # 2. Modify the LAST byte of ciphertext.
            # This often corrupts padding upon decryption.
            # AES CBC: Change in last block ciphertext -> change in last block plaintext.
            # If we flip the last byte, padding check should fail.
            # BUT: HMAC checks happens first. So HMAC should fail FIRST.
            # This proves Encrypt-Then-MAC security.
            print("[ATTACKER] Modifying last byte of ciphertext...")
            msg_list[-33] ^= (
                0x1  # -1 is last byte of HMAC, -33 is last byte of Ciphertext
            )

            s.sendall(bytes(msg_list))
            check_result(s, "Padding/HMAC")
    except Exception as e:
        print(f"[ERROR] {e}")


# --- 10. Wrong Client ID ---
def run_wrong_client_id_attack():
    print("\n--- ⚔️  SCENARIO 10: WRONG CLIENT ID IN HEADER ⚔️  ---")
    session = ProtocolSession(CLIENT_ID, MASTER_KEY, "client")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            # Handshake
            s.sendall(session.build_message(CLIENT_HELLO, b"HELLO", DIR_C2S))
            # Consume challenge
            s.recv(4096)

            # Send Data claiming to be Client 5
            # We manually pack the header
            iv = os.urandom(16)
            # Opcode 30, ID 5 (Wrong!), Round 0, Dir 1
            header = struct.pack("!BBIB", 30, 5, 0, 1) + iv

            # Encrypt and Sign using Client 1's keys
            key = session._aes_key(session.C2S_Enc)
            padded = b"100" + b"\x0d" * 13  # Manually padded
            from protocol_fsm import aes_cbc_encrypt, hmac_sha256

            ciphertext = aes_cbc_encrypt(key, iv, padded)
            hmac_val = hmac_sha256(session.C2S_Mac, header + ciphertext)

            s.sendall(header + ciphertext + hmac_val)
            check_result(s, "Client ID Mismatch")
    except Exception as e:
        print(f"[ERROR] {e}")


if __name__ == "__main__":
    print(f"Starting 10 Attack Scenarios against {HOST}:{PORT}...")

    attacks = [
        run_replay_attack,
        run_integrity_attack,
        run_desync_attack,
        run_reflection_attack,
        run_phase_violation_attack,
        run_impersonation_attack,
        run_truncation_attack,
        run_direction_flag_attack,
        run_padding_manipulation,
        run_wrong_client_id_attack,
    ]

    for i, attack in enumerate(attacks):
        attack()
        time.sleep(0.5)  # Give server time to reset thread/socket

    print("\n✅ All attack scenarios executed.")
