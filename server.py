import socket
import threading
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

HOST = "127.0.0.1"
PORT = 65432


class AnalyticsServer:
    def __init__(self):
        # Known set of valid clients [cite: 51]
        self.master_keys = {
            1: b"masterkey_client1_32bytes_long_!!",
            2: b"masterkey_client2_32bytes_long_!!",
            3: b"masterkey_client3_32bytes_long_!!",
            4: b"masterkey_client4_32bytes_long_!!",
        }

        # State Management
        # active_clients: Maps client_id -> ProtocolSession object
        self.active_clients = {}
        # round_data: Maps round_num -> {client_id: value}
        self.round_data = {}

        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)

    def handle_client(self, conn, addr):
        """
        Handles a single client connection in a separate thread.
        Does not block other clients.
        """
        print(f"[SERVER] Connection accepted from {addr}")
        client_id = None
        session = None

        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    break

                # --- Session Initialization ---
                if session is None:
                    # Identify Client from header (byte 1)
                    if len(data) < 2:
                        return
                    client_id = data[1]

                    if client_id not in self.master_keys:
                        print(f"[SERVER] Unknown Client {client_id}. Closing.")
                        return

                    # Create Session & Register as Active
                    # [cite: 19-22] Server maintains state per client
                    session = ProtocolSession(
                        client_id, self.master_keys[client_id], "server"
                    )

                    with self.lock:
                        self.active_clients[client_id] = session
                    print(f"[SERVER] Client {client_id} Active.")

                # --- Protocol Processing ---
                # parse_message handles HMAC, Replay, Round checks [cite: 23-27]
                try:
                    opcode, plaintext = session.parse_message(data, DIR_C2S)
                except Exception as e:
                    print(f"[SERVER] Security Error Client {client_id}: {e}")
                    # [cite: 27] Failure must permanently terminate session
                    break

                # --- Opcode Handling ---
                if opcode == CLIENT_HELLO:
                    # [cite: 114] Opcode 10 -> 20
                    resp = session.build_message(
                        SERVER_CHALLENGE, b"CHALLENGE", DIR_S2C
                    )
                    conn.sendall(resp)

                elif opcode == CLIENT_DATA:
                    # [cite: 114] Opcode 30 -> 40 (Aggregated)
                    val = int(plaintext.decode())

                    # Data belongs to the round *before* the current session state
                    # (since parse_message increments round internal counter)
                    current_round = session.round - 1

                    print(
                        f"[SERVER] Rx from Client {client_id} (Round {current_round}): {val}"
                    )

                    # Perform State-Based Aggregation [cite: 121]
                    agg_result = self.process_aggregation(client_id, current_round, val)

                    # Send Result
                    payload = str(agg_result).encode()
                    resp = session.build_message(SERVER_AGGR_RESPONSE, payload, DIR_S2C)
                    conn.sendall(resp)

                elif opcode == TERMINATE:
                    print(f"[SERVER] Client {client_id} Terminating.")
                    break

        except Exception as e:
            print(f"[SERVER] Connection Error: {e}")
        finally:
            conn.close()
            if client_id:
                with self.lock:
                    # Remove from active list so others don't wait for it
                    if client_id in self.active_clients:
                        del self.active_clients[client_id]
                    # Notify others that the group has changed
                    self.condition.notify_all()

    def process_aggregation(self, my_id, round_num, value):
        """
        Waits for all OTHER active clients currently at 'round_num' to submit data.
        This handles synchronization without fixed group sizes or timeouts.
        """
        with self.condition:
            # 1. Store my data
            if round_num not in self.round_data:
                self.round_data[round_num] = {}
            self.round_data[round_num][my_id] = value

            while True:
                # 2. Identify Peers: Active clients who are "sync-compatible"
                # A peer is relevant if they are active AND their session state indicates
                # they are currently working on (or just finished) this specific round.
                peers = []
                for cid, sess in self.active_clients.items():
                    # If sess.round == round_num + 1, it means that client has
                    # successfully parsed their incoming message for this round.
                    if sess.round == round_num + 1:
                        peers.append(cid)

                # 3. Check if we have data from all relevant peers
                # (Intersection of Peers and DataReceived)
                have_data_from = set(self.round_data[round_num].keys())
                needed_peers = set(peers)

                # If the set of peers we need is a subset of the data we have, we are done.
                if needed_peers.issubset(have_data_from):
                    # Aggregate (Summation) [cite: 121]
                    vals = [self.round_data[round_num][p] for p in needed_peers]
                    return sum(vals)

                # 4. If not, Wait for updates (new data or client disconnect)
                self.condition.wait()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            print(f"[SERVER] Listening on {HOST}:{PORT}")

            while True:
                # [cite: 50] Support multiple clients
                conn, addr = s.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr))
                t.daemon = True
                t.start()


if __name__ == "__main__":
    AnalyticsServer().start()
