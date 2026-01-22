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

# Configuration
HOST = "127.0.0.1"
PORT = 65432

# Master Keys mapping
KEYS = {
    1: b"masterkey_client1_32bytes_long_!!",
    2: b"masterkey_client2_32bytes_long_!!",
}


def run_client(client_id):
    if client_id not in KEYS:
        print("Invalid Client ID. Use 1 or 2.")
        return

    master_key = KEYS[client_id]
    session = ProtocolSession(client_id, master_key, "client")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"[CLIENT {client_id}] Connected.")

            # --- 1. Handshake ---
            # Send HELLO
            hello = session.build_message(CLIENT_HELLO, b"HELLO", DIR_C2S)
            s.sendall(hello)

            # Receive CHALLENGE
            data = s.recv(4096)
            opcode, _ = session.parse_message(data, DIR_S2C)
            if opcode != SERVER_CHALLENGE:
                print("[ERROR] Handshake failed")
                return

            print(f"[CLIENT {client_id}] Handshake Successful. Phase: {session.phase}")

            # --- 2. Data Transmission Loop ---
            # We will send 3 rounds of data
            for i in range(1, 4):
                # Data values: Client 1 sends 10, 20, 30. Client 2 sends 5, 5, 5.
                val = 10 * i if client_id == 1 else 5
                payload = str(val).encode()

                print(
                    f"\n[CLIENT {client_id}] Sending Data: {val} (Round {session.round})"
                )
                msg = session.build_message(CLIENT_DATA, payload, DIR_C2S)
                s.sendall(msg)

                print(f"[CLIENT {client_id}] Waiting for Server Aggregation...")
                resp_data = s.recv(4096)

                # Check for server disconnect or error
                if not resp_data:
                    break

                opcode, resp_plain = session.parse_message(resp_data, DIR_S2C)
                if opcode == SERVER_AGGR_RESPONSE:
                    print(
                        f"[CLIENT {client_id}] Received Aggregate: {resp_plain.decode()}"
                    )

                # Small sleep to make logs readable
                time.sleep(1)

            # --- 3. Termination ---
            term = session.build_message(TERMINATE, b"BYE", DIR_C2S)
            s.sendall(term)
            print(f"[CLIENT {client_id}] Session Terminated.")

    except Exception as e:
        print(f"[CLIENT {client_id}] Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cid = int(sys.argv[1])
    else:
        cid = int(input("Enter Client ID to run (1 or 2): "))

    run_client(cid)
