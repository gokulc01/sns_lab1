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

    def _evolve_keys(self, direction: int, ciphertext: bytes, nonce_or_data: bytes):
        """
        Updates keys based on the direction of the message just processed.
        nonce_or_data: IV (for C2S MAC update) or Plaintext (for S2C Enc update)
        """
        # [cite_start]Strictly enforce evolution only in ACTIVE phase [cite: 107]
        if self.phase != Phase.ACTIVE:
            return

        if direction == DIR_C2S:
            # C2S_Enc_{R+1} = H(C2S_Enc_R || Ciphertext_R)
            self.C2S_Enc = sha256(self.C2S_Enc + ciphertext)
            # C2S_Mac_{R+1} = H(C2S_Mac_R || Nonce_R) -> Using IV as Nonce
            self.C2S_Mac = sha256(self.C2S_Mac + nonce_or_data)
        else:
            # S2C_Enc_{R+1} = H(S2C_Enc_R || AggregatedData_R)
            self.S2C_Enc = sha256(self.S2C_Enc + nonce_or_data)
            # S2C_Mac_{R+1} = H(S2C_Mac_R || StatusCode_R) -> Using 1st byte of plaintext
            status = nonce_or_data[:1] if len(nonce_or_data) >= 1 else b"\x00"
            self.S2C_Mac = sha256(self.S2C_Mac + status)

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
        # Round must be consistent. If ACTIVE, we use current round.
        header = (
            struct.pack("!BBIB", opcode, self.client_id, self.round, direction) + iv
        )
        h = hmac_sha256(mac_key, header + ciphertext)

        # --- FIX 1: Sender State Update ---
        # The Sender MUST update their own state after sending, otherwise
        # they will be out of sync with the Receiver.
        if self.phase == Phase.ACTIVE:
            if direction == DIR_C2S:
                self._evolve_keys(direction, ciphertext, iv)  # Use IV as Nonce
            else:
                self._evolve_keys(direction, ciphertext, payload)  # Use Payload as Data

            self.round += 1

        # --- FIX 2: Delayed Server Transition ---
        # Server switches to ACTIVE only AFTER successfully building the Challenge.
        # This prevents the Challenge itself from triggering a key ratchet.
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

        # [cite_start]Check Round [cite: 24]
        if round_num != self.round:
            self.phase = Phase.TERMINATED
            raise ProtocolError(
                f"Round mismatch: Expected {self.round}, Got {round_num}"
            )

        # [cite_start]HMAC Verification [cite: 26]
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

        # [cite_start]Decryption [cite: 72]
        try:
            padded = aes_cbc_decrypt(aes_key, iv, ciphertext)
            plaintext = pkcs7_unpad(padded)
        except Exception:
            self.phase = Phase.TERMINATED
            raise ProtocolError("Decryption/padding failed")

        if not opcode_allowed(opcode, self.phase):
            self.phase = Phase.TERMINATED
            raise ProtocolError(f"Opcode {opcode} not allowed in {self.phase}")

        # --- FIX 3: Receiver State Update ---
        if self.phase == Phase.ACTIVE:
            if direction == DIR_C2S:
                self._evolve_keys(direction, ciphertext, iv)
            else:
                self._evolve_keys(direction, ciphertext, plaintext)
            self.round += 1

        # Phase Transitions
        # Client becomes ACTIVE after receiving Challenge
        if self.role == "client" and opcode == SERVER_CHALLENGE:
            self.phase = Phase.ACTIVE

        # Note: Server transition is handled in build_message (after sending Challenge)
        # to ensure the Challenge itself is sent using INIT keys.

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
