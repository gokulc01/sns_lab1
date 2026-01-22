import socket
import threading
import time
from protocol_fsm import (
    ProtocolSession,
    Phase,
    DIR_S2C,
    DIR_C2S,
    SERVER_CHALLENGE,
    SERVER_AGGR_RESPONSE,
    TERMINATE,
    CLIENT_HELLO,
    CLIENT_DATA,
)

# Hardcoded Configuration
HOST = "127.0.0.1"
PORT = 65432
REQUIRED_CLIENTS = 2


class AnalyticsServer:
    def __init__(self):
        # Hardcoded keys for exactly 2 clients
        self.master_keys = {
            1: b"masterkey_client1_32bytes_long_!!",
            2: b"masterkey_client2_32bytes_long_!!",
        }
        self.sessions = {}  # client_id -> ProtocolSession
        self.connections = {}  # client_id -> socket object

        # Aggregation Storage: { round_num: { client_id: value } }
        self.round_storage = {}
        self.lock = threading.Lock()

    def handle_client(self, conn, addr):
        print(f"[SERVER] Connection from {addr}")
        current_client_id = None

        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break

                # 1. Identify Client (First byte of header)
                if current_client_id is None:
                    current_client_id = data[1]
                    if current_client_id not in self.master_keys:
                        print(f"[SERVER] Invalid Client ID: {current_client_id}")
                        return

                    # Initialize Session
                    self.sessions[current_client_id] = ProtocolSession(
                        current_client_id, self.master_keys[current_client_id], "server"
                    )
                    self.connections[current_client_id] = conn
                    print(f"[SERVER] Client {current_client_id} Initialized")

                session = self.sessions[current_client_id]

                # 2. Parse Message
                # (Note: session.parse_message handles HMAC, Replay, etc.)
                opcode, plaintext = session.parse_message(data, DIR_C2S)

                # 3. Handle Opcodes
                if opcode == CLIENT_HELLO:
                    print(f"[SERVER] Received HELLO from Client {current_client_id}")
                    # Send Challenge (triggers INIT -> ACTIVE transition)
                    resp = session.build_message(
                        SERVER_CHALLENGE, b"CHALLENGE", DIR_S2C
                    )
                    conn.sendall(resp)

                elif opcode == CLIENT_DATA:
                    val = int(plaintext.decode())
                    current_round = (
                        session.round - 1
                    )  # Logic uses R-1 because round incremented after parse
                    print(
                        f"[SERVER] Rx Data from Client {current_client_id} (Round {current_round}): {val}"
                    )

                    self.process_aggregation(current_client_id, current_round, val)

                elif opcode == TERMINATE:
                    print(f"[SERVER] Client {current_client_id} Terminating")
                    break

        except Exception as e:
            print(f"[SERVER] Error with Client {current_client_id}: {e}")
        finally:
            conn.close()
            if current_client_id in self.connections:
                del self.connections[current_client_id]

    def process_aggregation(self, client_id, round_num, value):
        """Waits for 2 clients to submit data, then aggregates and responds."""
        with self.lock:
            if round_num not in self.round_storage:
                self.round_storage[round_num] = {}

            self.round_storage[round_num][client_id] = value

            # CHECK: Do we have data from both clients?
            if len(self.round_storage[round_num]) == REQUIRED_CLIENTS:
                # Aggregate (Summation)
                values = list(self.round_storage[round_num].values())
                agg_result = sum(values)
                print(
                    f"[SERVER] Aggregation Complete for Round {round_num}: {values} -> Sum: {agg_result}"
                )

                # Broadcast response to ALL connected clients
                self.broadcast_result(round_num, agg_result)

    def broadcast_result(self, round_num, result):
        # We must encrypt the SAME result separately for EACH client
        # using their distinct session keys.
        msg_payload = str(result).encode()

        for cid, conn in self.connections.items():
            session = self.sessions[cid]
            try:
                # Build message (this evolves Server keys for this client)
                resp = session.build_message(SERVER_AGGR_RESPONSE, msg_payload, DIR_S2C)
                conn.sendall(resp)
                print(f"[SERVER] Sent Result {result} to Client {cid}")
            except Exception as e:
                print(f"[SERVER] Failed to send to Client {cid}: {e}")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            print(
                f"[SERVER] Listening on {HOST}:{PORT} (Waiting for {REQUIRED_CLIENTS} clients)"
            )

            while True:
                conn, addr = s.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr))
                t.start()


if __name__ == "__main__":
    AnalyticsServer().start()
