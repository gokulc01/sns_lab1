import struct
from enum import Enum
from typing import Tuple
from crypto_utils import (
    pkcs7_pad,
    pkcs7_unpad,
    generate_iv,
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    hmac_sha256,
    sha256,
    secure_random,
)

# Opcodes
CLIENT_HELLO = 10
SERVER_CHALLENGE = 20
CLIENT_DATA = 30
SERVER_AGGR_RESPONSE = 40
KEY_DESYNC_ERROR = 50
TERMINATE = 60

DIR_C2S = 1
DIR_S2C = 2


class Phase(Enum):
    INIT = 0
    ACTIVE = 1
    TERMINATED = 2


class ProtocolError(Exception):
    pass


class ProtocolSession:
    def __init__(self, client_id: int, master_key: bytes, role: str):
        self.client_id = client_id
        self.role = role
        self.phase = Phase.INIT
        self.round = 0

        # [cite_start]Initialize keys (R=0) [cite: 85-98]
        self.C2S_Enc = sha256(master_key + b"C2S-ENC")
        self.C2S_Mac = sha256(master_key + b"C2S-MAC")
        self.S2C_Enc = sha256(master_key + b"S2C-ENC")
        self.S2C_Mac = sha256(master_key + b"S2C-MAC")

    def _aes_key(self, digest: bytes) -> bytes:
        return digest[:16]

    def _evolve_keys(
        self,
        direction: int,
        ciphertext: bytes,
        nonce_or_data: bytes,
        status_byte: bytes = b"\x00",
    ):
        """
        Updates keys based on the direction of the message just processed.

        Parameters:
        - direction: DIR_C2S or DIR_S2C
        - ciphertext: The ciphertext of the current message (used for C2S Enc evolution)
        - nonce_or_data:
            - [cite_start]If C2S: The IV (Nonce) [cite: 102]
            - [cite_start]If S2C: The Plaintext (AggregatedData) [cite: 105]
        - status_byte:
            - [cite_start]If S2C: The Opcode (StatusCode) [cite: 105]
        """
        if self.phase != Phase.ACTIVE:
            return

        if direction == DIR_C2S:
            # C2S_Enc_{R+1} = H(C2S_Enc_R || Ciphertext_R)
            self.C2S_Enc = sha256(self.C2S_Enc + ciphertext)

            # C2S_Mac_{R+1} = H(C2S_Mac_R || Nonce_R)
            # Use IV as the Nonce
            self.C2S_Mac = sha256(self.C2S_Mac + nonce_or_data)
        else:
            # S2C_Enc_{R+1} = H(S2C_Enc_R || AggregatedData_R)
            self.S2C_Enc = sha256(self.S2C_Enc + nonce_or_data)

            # S2C_Mac_{R+1} = H(S2C_Mac_R || StatusCode_R)
            # FIXED: Using the Opcode (passed as status_byte) as StatusCode
            self.S2C_Mac = sha256(self.S2C_Mac + status_byte)

    def build_message(self, opcode: int, payload: bytes, direction: int) -> bytes:
        iv = generate_iv()
        padded = pkcs7_pad(payload)

        if direction == DIR_C2S:
            key = self._aes_key(self.C2S_Enc)
            mac_key = self.C2S_Mac
        else:
            key = self._aes_key(self.S2C_Enc)
            mac_key = self.S2C_Mac

        ciphertext = aes_cbc_encrypt(key, iv, padded)
        header = (
            struct.pack("!BBIB", opcode, self.client_id, self.round, direction) + iv
        )
        h = hmac_sha256(mac_key, header + ciphertext)

        # --- Update Sender State ---
        if self.phase == Phase.ACTIVE:
            if direction == DIR_C2S:
                # C2S: Pass IV as Nonce
                self._evolve_keys(direction, ciphertext, iv)
            else:
                # S2C: Pass Payload as Data, Opcode as Status
                self._evolve_keys(direction, ciphertext, payload, bytes([opcode]))

            self.round += 1

        if self.role == "server" and opcode == SERVER_CHALLENGE:
            self.phase = Phase.ACTIVE

        return header + ciphertext + h

    def parse_message(self, raw: bytes, expected_direction: int) -> Tuple[int, bytes]:
        if self.phase == Phase.TERMINATED:
            raise ProtocolError("Session terminated")

        if len(raw) < 23 + 32:
            self.phase = Phase.TERMINATED
            raise ProtocolError("Message too short")

        header = raw[:23]
        opcode, client_id, round_num, direction = struct.unpack("!BBIB", header[:7])
        iv = header[7:23]
        ciphertext = raw[23:-32]
        recv_hmac = raw[-32:]

        if client_id != self.client_id or direction != expected_direction:
            self.phase = Phase.TERMINATED
            raise ProtocolError("Metadata mismatch")

        if round_num != self.round:
            self.phase = Phase.TERMINATED
            raise ProtocolError(
                f"Round mismatch: Expected {self.round}, Got {round_num}"
            )

        if direction == DIR_C2S:
            mac_key = self.C2S_Mac
            aes_key = self._aes_key(self.C2S_Enc)
        else:
            mac_key = self.S2C_Mac
            aes_key = self._aes_key(self.S2C_Enc)

        expected_h = hmac_sha256(mac_key, header + ciphertext)
        if not hmac_compare(expected_h, recv_hmac):
            self.phase = Phase.TERMINATED
            raise ProtocolError("HMAC verification failed")

        try:
            padded = aes_cbc_decrypt(aes_key, iv, ciphertext)
            plaintext = pkcs7_unpad(padded)
        except Exception:
            self.phase = Phase.TERMINATED
            raise ProtocolError("Decryption/padding failed")

        if not opcode_allowed(opcode, self.phase):
            self.phase = Phase.TERMINATED
            raise ProtocolError(f"Opcode {opcode} not allowed in {self.phase}")

        # --- Update Receiver State ---
        if self.phase == Phase.ACTIVE:
            if direction == DIR_C2S:
                # C2S: Pass IV as Nonce
                self._evolve_keys(direction, ciphertext, iv)
            else:
                # S2C: Pass Plaintext as Data, Opcode as Status
                self._evolve_keys(direction, ciphertext, plaintext, bytes([opcode]))
            self.round += 1

        if self.role == "client" and opcode == SERVER_CHALLENGE:
            self.phase = Phase.ACTIVE

        return opcode, plaintext


def opcode_allowed(opcode: int, phase: Phase) -> bool:
    if phase == Phase.TERMINATED:
        return False
    if phase == Phase.INIT:
        return opcode in (CLIENT_HELLO, SERVER_CHALLENGE, TERMINATE)
    if phase == Phase.ACTIVE:
        return opcode in (
            CLIENT_DATA,
            SERVER_AGGR_RESPONSE,
            KEY_DESYNC_ERROR,
            TERMINATE,
        )
    return False


def hmac_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    res = 0
    for x, y in zip(a, b):
        res |= x ^ y
    return res == 0
