import socket
import time
import sys
from protocol_fsm import (
    ProtocolSession,
    DIR_C2S,
    DIR_S2C,
    CLIENT_HELLO,
    SERVER_CHALLENGE,
    CLIENT_DATA,
    SERVER_AGGR_RESPONSE,
    TERMINATE,
)

HOST = "127.0.0.1"
PORT = 65432

# Expanded Key Store
KEYS = {
    1: b"masterkey_client1_32bytes_long_!!",
    2: b"masterkey_client2_32bytes_long_!!",
    3: b"masterkey_client3_32bytes_long_!!",
    4: b"masterkey_client4_32bytes_long_!!",
}


def run_client(client_id):
    if client_id not in KEYS:
        print(f"Error: No key found for Client {client_id}")
        return

    master_key = KEYS[client_id]
    # [cite: 83] Client initializes with Master Key
    session = ProtocolSession(client_id, master_key, "client")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"[CLIENT {client_id}] Connected.")

            # --- 1. Handshake Phase [cite: 114] ---
            print(f"[CLIENT {client_id}] Sending HELLO...")
            # Opcode 10
            hello = session.build_message(CLIENT_HELLO, b"HELLO", DIR_C2S)
            s.sendall(hello)

            # Expect Challenge (Opcode 20)
            data = s.recv(4096)
            opcode, _ = session.parse_message(data, DIR_S2C)

            if opcode == SERVER_CHALLENGE:
                print(f"[CLIENT {client_id}] Handshake Successful. Active.")
            else:
                print(f"[CLIENT {client_id}] Handshake Failed. Opcode: {opcode}")
                return

            # --- 2. Data Transmission Phase [cite: 100] ---
            # Sending 5 rounds to demonstrate continuous sync
            for i in range(1, 6):
                # Unique value calculation for demo
                val = 10 * client_id
                payload = str(val).encode()

                print(f"[CLIENT {client_id}] Sending: {val} (Round {session.round})")

                # [cite: 60-67] Encrypt & Authenticate
                msg = session.build_message(CLIENT_DATA, payload, DIR_C2S)
                s.sendall(msg)

                # Wait for Aggregated Response
                resp_data = s.recv(4096)
                if not resp_data:
                    print(f"[CLIENT {client_id}] Server disconnected.")
                    break

                # [cite: 68-75] Decrypt & Verify
                opcode, plain = session.parse_message(resp_data, DIR_S2C)

                if opcode == SERVER_AGGR_RESPONSE:
                    print(f"[CLIENT {client_id}] Round {i} Result: {plain.decode()}")

                # Sleep just to make manual terminal observation easier
                time.sleep(1)

            # --- 3. Termination [cite: 27] ---
            print(f"[CLIENT {client_id}] Sending TERMINATE.")
            term = session.build_message(TERMINATE, b"BYE", DIR_C2S)
            s.sendall(term)

    except Exception as e:
        print(f"[CLIENT {client_id}] Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python client.py <client_id>")
        print("Example: python client.py 1")
    else:
        run_client(int(sys.argv[1]))
