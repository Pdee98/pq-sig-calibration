import os
from dataclasses import dataclass
from uuid import uuid4

from src.crypto.base import BackendInfo, CryptoBackend, message_to_bytes
from src.crypto.hash_utils import base_w, lmots_checksum_digits, lmots_parameters, sha256, u32


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def u8(value: int) -> bytes:
    return bytes([value])


@dataclass
class LMSKeyPair:
    identifier: bytes
    seed: bytes
    root: bytes
    tree_levels: list[list[bytes]]
    next_index: int = 0


@dataclass
class LMSIndexReservation:
    signer_id: int
    public_key_identity: str
    key_generation: int
    index: int
    token: str
    consumed: bool = False


class LMSBackend(CryptoBackend):
    """Pure-Python LMS_SHA256_M32_H10 with RFC 8554 LMOTS parameters.

    The layout follows RFC 8554: LM-OTS parameters/signing/verification
    (Section 4), LMS Merkle tree signing and path verification (Section 5),
    and required state advancement before signature release (Section 5.4.1).
    """

    D_PBLC = 0x8080
    D_MESG = 0x8181
    D_LEAF = 0x8282
    D_INTR = 0x8383

    LMS_TYPES = {5: 0x00000005, 10: 0x00000006, 15: 0x00000007, 20: 0x00000008, 25: 0x00000009}
    LMS_TYPE_TO_HEIGHT = {value: key for key, value in LMS_TYPES.items()}
    LMOTS_TYPE_TO_W = {0x00000001: 1, 0x00000002: 2, 0x00000003: 4, 0x00000004: 8}

    def __init__(self, height: int = 10, n: int = 32, w: int = 4):
        if height not in self.LMS_TYPES:
            raise ValueError(f"unsupported RFC 8554 LMS height: {height}")
        self.height = height
        self.n = n
        self.w = w
        self.lmots_type, self.len_1, self.len_2, self.p, self.ls, self.lmots_sig_len = (
            lmots_parameters(n, w)
        )
        self.lms_type = self.LMS_TYPES[height]
        self.base = 1 << w
        self.max_signatures = 1 << height
        self.keypairs = {}
        self._key_generations = {}
        self._reservations = {}
        self._last_signature_size = self._signature_size()

    def _ensure_keypair(self, signer_id: int) -> None:
        if signer_id in self.keypairs:
            return
        self.generate_new_signer(signer_id)

    def generate_new_signer(self, signer_id: int) -> None:
        self._key_generations[signer_id] = self._key_generations.get(signer_id, -1) + 1
        self._reservations = {
            token: reservation
            for token, reservation in self._reservations.items()
            if reservation.signer_id != signer_id
        }
        identifier = os.urandom(16)
        seed = os.urandom(self.n)
        leaves = [
            self._leaf_value(identifier, seed, q)
            for q in range(self.max_signatures)
        ]
        tree_levels = [leaves]
        current = leaves
        node_start = 1 << self.height
        while len(current) > 1:
            current = [
                self._internal_node_value(
                    identifier,
                    (node_start + i) // 2,
                    current[i],
                    current[i + 1],
                )
                for i in range(0, len(current), 2)
            ]
            tree_levels.append(current)
            node_start //= 2
        self.keypairs[signer_id] = LMSKeyPair(
            identifier=identifier,
            seed=seed,
            root=tree_levels[-1][0],
            tree_levels=tree_levels,
        )

    def _ots_private_element(self, identifier: bytes, seed: bytes, q: int, i: int) -> bytes:
        return sha256(identifier + u32(q) + u16(i) + u8(0xFF) + seed)

    def _coef_digits(self, digest: bytes) -> list[int]:
        msg = base_w(digest, self.len_1, self.base)
        return msg + lmots_checksum_digits(msg, self.len_2, self.w, self.ls)

    def _chain(self, value: bytes, identifier: bytes, q: int, i: int, start: int, steps: int) -> bytes:
        result = value
        for j in range(start, start + steps):
            result = sha256(identifier + u32(q) + u16(i) + u8(j) + result)
        return result

    def _lmots_public_key(self, identifier: bytes, seed: bytes, q: int) -> bytes:
        values = [
            self._chain(
                self._ots_private_element(identifier, seed, q, i),
                identifier,
                q,
                i,
                0,
                self.base - 1,
            )
            for i in range(self.p)
        ]
        return sha256(identifier + u32(q) + u16(self.D_PBLC) + b"".join(values))

    def _lmots_signature(self, identifier: bytes, seed: bytes, q: int, message: bytes) -> bytes:
        c = os.urandom(self.n)
        digest = sha256(identifier + u32(q) + u16(self.D_MESG) + c + message)
        digits = self._coef_digits(digest)
        y_values = [
            self._chain(
                self._ots_private_element(identifier, seed, q, i),
                identifier,
                q,
                i,
                0,
                digits[i],
            )
            for i in range(self.p)
        ]
        return u32(self.lmots_type) + c + b"".join(y_values)

    def _lmots_parameters_for_type(self, lmots_type: int) -> tuple[int, int, int, int, int, int, int] | None:
        w_bits = self.LMOTS_TYPE_TO_W.get(lmots_type)
        if w_bits is None:
            return None
        parsed_type, len_1, len_2, p, ls, sig_len = lmots_parameters(self.n, w_bits)
        if parsed_type != lmots_type:
            return None
        return w_bits, len_1, len_2, p, ls, sig_len, 1 << w_bits

    def _coef_digits_for_params(
        self,
        digest: bytes,
        len_1: int,
        len_2: int,
        w_bits: int,
        base: int,
        ls: int,
    ) -> list[int]:
        msg = base_w(digest, len_1, base)
        return msg + lmots_checksum_digits(msg, len_2, w_bits, ls)

    def _lmots_public_key_from_signature(
        self,
        identifier: bytes,
        q: int,
        signature: bytes,
        message: bytes,
        expected_lmots_type: int | None = None,
    ) -> bytes | None:
        if len(signature) < 4:
            return None
        lmots_type = int.from_bytes(signature[:4], "big")
        if expected_lmots_type is not None and lmots_type != expected_lmots_type:
            return None
        params = self._lmots_parameters_for_type(lmots_type)
        if params is None:
            return None
        w_bits, len_1, len_2, p, ls, sig_len, base = params
        expected_len = sig_len
        if len(signature) != expected_len:
            return None
        c = signature[4:4 + self.n]
        y_blob = signature[4 + self.n:]
        y_values = [y_blob[i:i + self.n] for i in range(0, len(y_blob), self.n)]
        digest = sha256(identifier + u32(q) + u16(self.D_MESG) + c + message)
        digits = self._coef_digits_for_params(digest, len_1, len_2, w_bits, base, ls)
        values = [
            self._chain(y_values[i], identifier, q, i, digits[i], base - 1 - digits[i])
            for i in range(p)
        ]
        return sha256(identifier + u32(q) + u16(self.D_PBLC) + b"".join(values))

    def _leaf_node_value(self, identifier: bytes, node_num: int, ots_pk: bytes) -> bytes:
        return sha256(identifier + u32(node_num) + u16(self.D_LEAF) + ots_pk)

    def _internal_node_value(self, identifier: bytes, node_num: int, left: bytes, right: bytes) -> bytes:
        return sha256(identifier + u32(node_num) + u16(self.D_INTR) + left + right)

    def _leaf_value(self, identifier: bytes, seed: bytes, q: int) -> bytes:
        ots_pk = self._lmots_public_key(identifier, seed, q)
        return self._leaf_node_value(identifier, (1 << self.height) + q, ots_pk)

    def _auth_path(self, keypair: LMSKeyPair, q: int) -> list[bytes]:
        path = []
        node_index = q
        for level in range(self.height):
            path.append(keypair.tree_levels[level][node_index ^ 1])
            node_index //= 2
        return path

    def _root_from_leaf(self, identifier: bytes, q: int, leaf: bytes, path: list[bytes], height: int) -> bytes:
        node = leaf
        node_num = (1 << height) + q
        for sibling in path:
            parent_index = node_num // 2
            if node_num % 2 == 0:
                node = self._internal_node_value(identifier, parent_index, node, sibling)
            else:
                node = self._internal_node_value(identifier, parent_index, sibling, node)
            node_num = parent_index
        return node

    def _signature_size(self) -> int:
        return 4 + self.lmots_sig_len + 4 + self.height * self.n

    def reserve_index(self, signer_id: int) -> LMSIndexReservation:
        self._ensure_keypair(signer_id)
        keypair = self.keypairs[signer_id]
        if keypair.next_index >= self.max_signatures:
            raise ValueError(f"LMS state exhausted for signer {signer_id}")
        q = keypair.next_index
        keypair.next_index += 1
        reservation = LMSIndexReservation(
            signer_id=signer_id,
            public_key_identity=self.get_public_key_identity(signer_id),
            key_generation=self._key_generations[signer_id],
            index=q,
            token=uuid4().hex,
        )
        self._reservations[reservation.token] = reservation
        return reservation

    def sign_reserved_index(self, message: str | bytes, signer_id: int, reservation: LMSIndexReservation) -> bytes:
        self._ensure_keypair(signer_id)
        if not isinstance(reservation, LMSIndexReservation):
            raise ValueError("LMS signing requires an active reservation")
        active = self._reservations.get(reservation.token)
        if active is not reservation or reservation.consumed:
            raise ValueError("LMS reservation is not active")
        if reservation.signer_id != signer_id:
            raise ValueError("LMS reservation signer mismatch")
        if reservation.key_generation != self._key_generations.get(signer_id):
            raise ValueError("LMS reservation generation mismatch")
        if reservation.public_key_identity != self.get_public_key_identity(signer_id):
            raise ValueError("LMS reservation public key mismatch")
        reservation.consumed = True
        self._reservations.pop(reservation.token, None)
        q = reservation.index
        keypair = self.keypairs[signer_id]
        if isinstance(q, bool) or not isinstance(q, int) or q < 0 or q >= self.max_signatures:
            raise ValueError("reserved LMS index is invalid")
        signature = (
            u32(q)
            + self._lmots_signature(keypair.identifier, keypair.seed, q, message_to_bytes(message))
            + u32(self.lms_type)
            + b"".join(self._auth_path(keypair, q))
        )
        self._last_signature_size = len(signature)
        return signature

    def sign(self, message: str | bytes, signer_id: int) -> bytes:
        reservation = self.reserve_index(signer_id)
        return self.sign_reserved_index(message, signer_id, reservation)

    def _public_key_bytes(self, keypair: LMSKeyPair) -> bytes:
        return u32(self.lms_type) + u32(self.lmots_type) + keypair.identifier + keypair.root

    def get_public_key_bytes(self, signer_id: int) -> bytes:
        self._ensure_keypair(signer_id)
        return self._public_key_bytes(self.keypairs[signer_id])

    def get_public_key_identity(self, signer_id: int) -> str:
        return sha256(self.get_public_key_bytes(signer_id)).hex()

    def get_key_generation(self, signer_id: int) -> int:
        self._ensure_keypair(signer_id)
        return self._key_generations[signer_id]

    def get_next_index(self, signer_id: int) -> int:
        self._ensure_keypair(signer_id)
        return self.keypairs[signer_id].next_index

    def advance_next_index_floor(self, signer_id: int, next_index: int) -> None:
        self._ensure_keypair(signer_id)
        if isinstance(next_index, bool) or not isinstance(next_index, int) or next_index < 0 or next_index > self.max_signatures:
            raise ValueError("next_index floor is invalid")
        if self.keypairs[signer_id].next_index < next_index:
            self.keypairs[signer_id].next_index = next_index

    def get_max_signatures(self) -> int:
        return self.max_signatures

    def extract_leaf_index(self, signature: bytes) -> int | None:
        if len(signature) < 4:
            return None
        q = int.from_bytes(signature[:4], "big")
        if q >= self.max_signatures:
            return None
        return q

    def verify_with_public_key(self, message: str | bytes, signature: bytes, public_key: bytes) -> bool:
        if len(public_key) != self.get_public_key_size():
            return False
        if len(signature) < 12:
            return False

        lms_type = int.from_bytes(public_key[:4], "big")
        lmots_type = int.from_bytes(public_key[4:8], "big")
        height = self.LMS_TYPE_TO_HEIGHT.get(lms_type)
        lmots_params = self._lmots_parameters_for_type(lmots_type)
        if height is None or lmots_params is None:
            return False
        _, _, _, p, _, lmots_sig_len, _ = lmots_params
        identifier = public_key[8:24]
        public_root = public_key[24:56]
        expected_signature_len = 4 + lmots_sig_len + 4 + height * self.n
        if len(signature) != expected_signature_len:
            return False

        cursor = 0
        q = int.from_bytes(signature[cursor:cursor + 4], "big")
        cursor += 4
        if q >= (1 << height):
            return False
        lmots_len = 4 + self.n + p * self.n
        lmots_sig = signature[cursor:cursor + lmots_len]
        cursor += lmots_len
        if int.from_bytes(signature[cursor:cursor + 4], "big") != lms_type:
            return False
        cursor += 4
        auth_blob = signature[cursor:]
        path = [auth_blob[i:i + self.n] for i in range(0, len(auth_blob), self.n)]
        ots_pk = self._lmots_public_key_from_signature(
            identifier,
            q,
            lmots_sig,
            message_to_bytes(message),
            expected_lmots_type=lmots_type,
        )
        if ots_pk is None:
            return False
        leaf = self._leaf_node_value(identifier, (1 << height) + q, ots_pk)
        return self._root_from_leaf(identifier, q, leaf, path, height) == public_root

    def verify(self, message: str | bytes, signature: bytes, signer_id: int) -> bool:
        self._ensure_keypair(signer_id)
        return self.verify_with_public_key(
            message,
            signature,
            self._public_key_bytes(self.keypairs[signer_id]),
        )

    def prepare_signer(self, signer_id: int) -> None:
        self._ensure_keypair(signer_id)

    def get_name(self) -> str:
        return f"lms_sha256_m32_h{self.height}_lmots_w{self.w}"

    def get_signature_size(self) -> int:
        return self._last_signature_size

    def get_public_key_size(self) -> int:
        return 4 + 4 + 16 + self.n

    def get_private_key_size(self) -> int:
        self._ensure_keypair(0)
        return 16 + self.n + 4

    def get_info(self) -> BackendInfo:
        return BackendInfo(
            name=self.get_name(),
            parameter_set=(
                f"LMS_SHA256_M32_H{self.height} + LMOTS_SHA256_N32_W{self.w} "
                f"(w_bits={self.w}, base={self.base}, p={self.p}, ls={self.ls}, "
                f"lms_type=0x{self.lms_type:08x}, lmots_type=0x{self.lmots_type:08x})"
            ),
            implementation="pure Python LMS/LMOTS implementation",
            language="Python",
            signature_size=self._signature_size(),
            public_key_size=self.get_public_key_size(),
            conformance_status=(
                "RFC 8554 domain separators, serialization, and Appendix F verification path implemented; "
                "not a formally validated conformance implementation"
            ),
        )
