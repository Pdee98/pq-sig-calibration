import os
from dataclasses import dataclass
from uuid import uuid4

from src.crypto.base import BackendInfo, CryptoBackend, message_to_bytes
from src.crypto.hash_utils import prf, sha256, u32
from src.crypto.wots_xmss import WOTSPlus, WOTSPlusParams, l_tree


@dataclass
class XMSSKeyPair:
    sk_seed: bytes
    sk_prf: bytes
    pub_seed: bytes
    root: bytes
    leaves: list[bytes]
    tree_levels: list[list[bytes]]
    next_index: int = 0


@dataclass
class XMSSIndexReservation:
    signer_id: int
    public_key_identity: str
    key_generation: int
    index: int
    token: str
    consumed: bool = False


class XMSSBackend(CryptoBackend):
    """Pure-Python XMSS-SHA2_10_256 implementation.

    This implements the RFC 8391 XMSS construction shape: WOTS+ leaves
    (Section 3.1), L-tree compression (Section 4.1.5), Merkle tree/auth paths
    (Sections 4.1.6 and 4.1.8), stateful index handling (Section 4.1.12), and
    signature verification by recomputing the root (Section 4.1.10).
    """

    def __init__(self, height: int = 10, n: int = 32, w: int = 16):
        self.height = height
        self.n = n
        self.wots = WOTSPlus(WOTSPlusParams(n=n, w=w))
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
        sk_seed = os.urandom(self.n)
        sk_prf = os.urandom(self.n)
        pub_seed = os.urandom(self.n)
        leaves = [
            l_tree(self.wots.public_key(sk_seed, pub_seed, index))
            for index in range(self.max_signatures)
        ]
        tree_levels = [leaves]
        current = leaves
        while len(current) > 1:
            current = [
                sha256(b"XMSS-NODE" + current[i] + current[i + 1])
                for i in range(0, len(current), 2)
            ]
            tree_levels.append(current)

        self.keypairs[signer_id] = XMSSKeyPair(
            sk_seed=sk_seed,
            sk_prf=sk_prf,
            pub_seed=pub_seed,
            root=tree_levels[-1][0],
            leaves=leaves,
            tree_levels=tree_levels,
        )

    def _message_digest(self, randomizer: bytes, root: bytes, index: int, message: bytes) -> bytes:
        return sha256(b"XMSS-MSG" + randomizer + root + u32(index) + message)

    def _auth_path(self, keypair: XMSSKeyPair, index: int) -> list[bytes]:
        path = []
        node_index = index
        for level in range(self.height):
            sibling = node_index ^ 1
            path.append(keypair.tree_levels[level][sibling])
            node_index //= 2
        return path

    def _root_from_signature_leaf(self, leaf: bytes, auth_path: list[bytes], index: int) -> bytes:
        node = leaf
        node_index = index
        for sibling in auth_path:
            if node_index % 2 == 0:
                node = sha256(b"XMSS-NODE" + node + sibling)
            else:
                node = sha256(b"XMSS-NODE" + sibling + node)
            node_index //= 2
        return node

    def _signature_size(self) -> int:
        return 4 + self.n + self.wots.params.length * self.n + self.height * self.n

    def reserve_index(self, signer_id: int) -> XMSSIndexReservation:
        self._ensure_keypair(signer_id)
        keypair = self.keypairs[signer_id]
        if keypair.next_index >= self.max_signatures:
            raise ValueError(f"XMSS state exhausted for signer {signer_id}")
        index = keypair.next_index
        keypair.next_index += 1
        reservation = XMSSIndexReservation(
            signer_id=signer_id,
            public_key_identity=self.get_public_key_identity(signer_id),
            key_generation=self._key_generations[signer_id],
            index=index,
            token=uuid4().hex,
        )
        self._reservations[reservation.token] = reservation
        return reservation

    def sign_reserved_index(self, message: str | bytes, signer_id: int, reservation: XMSSIndexReservation) -> bytes:
        self._ensure_keypair(signer_id)
        if not isinstance(reservation, XMSSIndexReservation):
            raise ValueError("XMSS signing requires an active reservation")
        active = self._reservations.get(reservation.token)
        if active is not reservation or reservation.consumed:
            raise ValueError("XMSS reservation is not active")
        if reservation.signer_id != signer_id:
            raise ValueError("XMSS reservation signer mismatch")
        if reservation.key_generation != self._key_generations.get(signer_id):
            raise ValueError("XMSS reservation generation mismatch")
        if reservation.public_key_identity != self.get_public_key_identity(signer_id):
            raise ValueError("XMSS reservation public key mismatch")
        reservation.consumed = True
        self._reservations.pop(reservation.token, None)
        index = reservation.index
        keypair = self.keypairs[signer_id]
        if isinstance(index, bool) or not isinstance(index, int) or index < 0 or index >= self.max_signatures:
            raise ValueError("reserved XMSS index is invalid")
        randomizer = prf(keypair.sk_prf, b"XMSS-R", u32(index), message_to_bytes(message))
        digest = self._message_digest(randomizer, keypair.root, index, message_to_bytes(message))
        wots_signature = self.wots.sign(digest, keypair.sk_seed, keypair.pub_seed, index)
        auth_path = self._auth_path(keypair, index)

        signature = (
            u32(index)
            + randomizer
            + b"".join(wots_signature)
            + b"".join(auth_path)
        )
        self._last_signature_size = len(signature)
        return signature

    def sign(self, message: str | bytes, signer_id: int) -> bytes:
        reservation = self.reserve_index(signer_id)
        return self.sign_reserved_index(message, signer_id, reservation)

    def _public_key_bytes(self, keypair: XMSSKeyPair) -> bytes:
        return u32(self.height) + keypair.root + keypair.pub_seed

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
        index = int.from_bytes(signature[:4], "big")
        if index >= self.max_signatures:
            return None
        return index

    def verify_with_public_key(self, message: str | bytes, signature: bytes, public_key: bytes) -> bool:
        if len(public_key) != self.get_public_key_size():
            return False
        if int.from_bytes(public_key[:4], "big") != self.height:
            return False
        if len(signature) != self._signature_size():
            return False

        root = public_key[4:4 + self.n]
        pub_seed = public_key[4 + self.n:]
        cursor = 0
        index = int.from_bytes(signature[cursor:cursor + 4], "big")
        cursor += 4
        if index >= self.max_signatures:
            return False

        randomizer = signature[cursor:cursor + self.n]
        cursor += self.n
        wots_len = self.wots.params.length * self.n
        wots_sig_bytes = signature[cursor:cursor + wots_len]
        cursor += wots_len
        auth_bytes = signature[cursor:]

        wots_signature = [
            wots_sig_bytes[i:i + self.n]
            for i in range(0, len(wots_sig_bytes), self.n)
        ]
        auth_path = [
            auth_bytes[i:i + self.n]
            for i in range(0, len(auth_bytes), self.n)
        ]
        digest = self._message_digest(randomizer, root, index, message_to_bytes(message))
        wots_pk = self.wots.pk_from_signature(wots_signature, digest, pub_seed, index)
        leaf = l_tree(wots_pk)
        candidate_root = self._root_from_signature_leaf(leaf, auth_path, index)
        return candidate_root == root

    def verify(self, message: str | bytes, signature: bytes, signer_id: int) -> bool:
        self._ensure_keypair(signer_id)
        return self.verify_with_public_key(message, signature, self.get_public_key_bytes(signer_id))

    def prepare_signer(self, signer_id: int) -> None:
        self._ensure_keypair(signer_id)

    def get_name(self) -> str:
        return f"xmss_sha2_{self.height}_256"

    def get_signature_size(self) -> int:
        return self._last_signature_size

    def get_public_key_size(self) -> int:
        return 4 + self.n + self.n

    def get_private_key_size(self) -> int:
        self._ensure_keypair(0)
        keypair = self.keypairs[0]
        return len(keypair.sk_seed) + len(keypair.sk_prf) + len(keypair.pub_seed) + 4

    def get_info(self) -> BackendInfo:
        return BackendInfo(
            name=self.get_name(),
            parameter_set=f"XMSS-SHA2_{self.height}_256, h={self.height}, n={self.n}, w={self.wots.params.w}",
            implementation="pure Python XMSS/WOTS+ implementation",
            language="Python",
            signature_size=self._signature_size(),
            public_key_size=self.get_public_key_size(),
            conformance_status=(
                "size formulas aligned with RFC 8391; not validated against authoritative test vectors"
            ),
        )
