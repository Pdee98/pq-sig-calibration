import importlib
import os
from dataclasses import dataclass

from src.crypto.base import BackendInfo, CryptoBackend, message_to_bytes
from src.crypto.hash_utils import prf, sha256, u32
from src.crypto.wots_xmss import WOTSPlus, WOTSPlusParams, l_tree


@dataclass
class _SLHTree:
    leaves: list[bytes]
    levels: list[list[bytes]]
    root: bytes


class _PurePythonSLHFallback(CryptoBackend):
    """Stateless hash-based fallback used when PySPX cannot be installed.

    This is a SPHINCS+-style hypertree of WOTS+ Merkle trees. It is real
    hash-based signing and verification with deterministic per-message leaf
    selection, but it is not a FIPS 205 conformance implementation.
    """

    def __init__(self, layers: int = 4, height: int = 8, n: int = 32, w: int = 16):
        self.layers = layers
        self.height = height
        self.n = n
        self.wots = WOTSPlus(WOTSPlusParams(n=n, w=w))
        self.leaves_per_tree = 1 << height
        self.signer_seeds = {}
        self.signer_trees = {}
        self._last_signature_size = self._signature_size()

    def _ensure_keypair(self, signer_id: int) -> None:
        if signer_id in self.signer_trees:
            return
        seed = os.urandom(self.n)
        pub_seed = os.urandom(self.n)
        trees = []
        for layer in range(self.layers):
            leaves = [
                l_tree(self.wots.public_key(self._sk_seed(seed, layer), pub_seed, leaf_index))
                for leaf_index in range(self.leaves_per_tree)
            ]
            levels = [leaves]
            current = leaves
            while len(current) > 1:
                current = [
                    sha256(b"SLH-NODE" + u32(layer) + current[i] + current[i + 1])
                    for i in range(0, len(current), 2)
                ]
                levels.append(current)
            trees.append(_SLHTree(leaves=leaves, levels=levels, root=levels[-1][0]))
        self.signer_seeds[signer_id] = (seed, pub_seed)
        self.signer_trees[signer_id] = trees

    def _sk_seed(self, seed: bytes, layer: int) -> bytes:
        return prf(seed, b"SLH-LAYER-SK", u32(layer))

    def _leaf_index(self, randomizer: bytes, layer: int, value: bytes) -> int:
        digest = sha256(b"SLH-IDX" + randomizer + u32(layer) + value)
        return int.from_bytes(digest[:4], "big") % self.leaves_per_tree

    def _auth_path(self, tree: _SLHTree, index: int) -> list[bytes]:
        path = []
        node_index = index
        for level in range(self.height):
            path.append(tree.levels[level][node_index ^ 1])
            node_index //= 2
        return path

    def _root_from_leaf(self, layer: int, leaf: bytes, auth_path: list[bytes], index: int) -> bytes:
        node = leaf
        node_index = index
        for sibling in auth_path:
            if node_index % 2 == 0:
                node = sha256(b"SLH-NODE" + u32(layer) + node + sibling)
            else:
                node = sha256(b"SLH-NODE" + u32(layer) + sibling + node)
            node_index //= 2
        return node

    def _signature_size(self) -> int:
        layer_size = 4 + self.wots.params.length * self.n + self.height * self.n
        return self.n + self.layers * layer_size

    def sign(self, message: str | bytes, signer_id: int) -> bytes:
        self._ensure_keypair(signer_id)
        seed, pub_seed = self.signer_seeds[signer_id]
        trees = self.signer_trees[signer_id]
        message_bytes = message_to_bytes(message)
        randomizer = os.urandom(self.n)
        value = sha256(b"SLH-MSG" + randomizer + message_bytes)
        parts = [randomizer]
        for layer in range(self.layers):
            index = self._leaf_index(randomizer, layer, value)
            digest = sha256(b"SLH-WOTS-MSG" + u32(layer) + value)
            wots_signature = self.wots.sign(
                digest,
                self._sk_seed(seed, layer),
                pub_seed,
                index,
            )
            auth_path = self._auth_path(trees[layer], index)
            parts.append(u32(index) + b"".join(wots_signature) + b"".join(auth_path))
            value = trees[layer].root
        signature = b"".join(parts)
        self._last_signature_size = len(signature)
        return signature

    def verify(self, message: str | bytes, signature: bytes, signer_id: int) -> bool:
        self._ensure_keypair(signer_id)
        _, pub_seed = self.signer_seeds[signer_id]
        trees = self.signer_trees[signer_id]
        if len(signature) != self._signature_size():
            return False

        cursor = 0
        randomizer = signature[cursor:cursor + self.n]
        cursor += self.n
        value = sha256(b"SLH-MSG" + randomizer + message_to_bytes(message))
        for layer in range(self.layers):
            index = int.from_bytes(signature[cursor:cursor + 4], "big")
            cursor += 4
            if index >= self.leaves_per_tree:
                return False
            wots_len = self.wots.params.length * self.n
            wots_blob = signature[cursor:cursor + wots_len]
            cursor += wots_len
            auth_blob = signature[cursor:cursor + self.height * self.n]
            cursor += self.height * self.n
            wots_signature = [wots_blob[i:i + self.n] for i in range(0, len(wots_blob), self.n)]
            auth_path = [auth_blob[i:i + self.n] for i in range(0, len(auth_blob), self.n)]
            digest = sha256(b"SLH-WOTS-MSG" + u32(layer) + value)
            wots_pk = self.wots.pk_from_signature(wots_signature, digest, pub_seed, index)
            leaf = l_tree(wots_pk)
            value = self._root_from_leaf(layer, leaf, auth_path, index)

        return value == trees[-1].root

    def prepare_signer(self, signer_id: int) -> None:
        self._ensure_keypair(signer_id)

    def get_name(self) -> str:
        return "slh_dsa_pure_python_fallback"

    def get_signature_size(self) -> int:
        return self._last_signature_size

    def get_public_key_size(self) -> int:
        return 2 * self.n

    def get_private_key_size(self) -> int:
        return 2 * self.n

    def get_info(self) -> BackendInfo:
        return BackendInfo(
            name=self.get_name(),
            parameter_set="SPHINCS+-style WOTS+ hypertree, d=4, h=8 per layer",
            implementation="pure Python fallback; not FIPS 205 conformant",
            language="Python",
            signature_size=self._signature_size(),
            public_key_size=self.get_public_key_size(),
            conformance_status="fallback only; not FIPS 205 conformant",
        )


class SLHDSABackend(CryptoBackend):
    """SPHINCS+/SLH-DSA-style backend using the real PySPX bindings.

    PySPX wraps the SPHINCS+ reference implementation. FIPS 205 standardized
    SLH-DSA from SPHINCS+; this backend uses the closest available PySPX
    parameter module and records that exact module in get_info().
    """

    def __init__(self, parameter_module: str | None = None, fallback_options: dict | None = None):
        self._fallback = None
        try:
            self.parameter_module = parameter_module or self._select_parameter_module()
            self.spx = importlib.import_module(self.parameter_module)
        except ImportError:
            if parameter_module is not None:
                raise
            self.parameter_module = "pure_python_fallback"
            self.spx = None
            self._fallback = _PurePythonSLHFallback(**(fallback_options or {}))
            return
        self.public_keys = {}
        self.secret_keys = {}
        self._last_signature_size = int(self.spx.crypto_sign_BYTES)

    def _select_parameter_module(self) -> str:
        candidates = [
            "pyspx.sha2_128s",
            "pyspx.shake_128s",
            "pyspx.sha2_128f",
            "pyspx.shake_128f",
        ]
        for candidate in candidates:
            try:
                importlib.import_module(candidate)
                return candidate
            except ImportError:
                continue
        raise ImportError(
            "PySPX is required for the SLH-DSA/SPHINCS+ backend. "
            "Install it with `pip install pyspx`."
        )

    def _ensure_keypair(self, signer_id: int) -> None:
        if self._fallback is not None:
            self._fallback.prepare_signer(signer_id)
            return
        if signer_id in self.secret_keys:
            return
        seed_len = int(self.spx.crypto_sign_SEEDBYTES)
        public_key, secret_key = self.spx.generate_keypair(os.urandom(seed_len))
        self.public_keys[signer_id] = public_key
        self.secret_keys[signer_id] = secret_key

    def sign(self, message: str | bytes, signer_id: int) -> bytes:
        if self._fallback is not None:
            return self._fallback.sign(message, signer_id)
        self._ensure_keypair(signer_id)
        signature = self.spx.sign(message_to_bytes(message), self.secret_keys[signer_id])
        self._last_signature_size = len(signature)
        return signature

    def prepare_signer(self, signer_id: int) -> None:
        self._ensure_keypair(signer_id)

    def verify(self, message: str | bytes, signature: bytes, signer_id: int) -> bool:
        if self._fallback is not None:
            return self._fallback.verify(message, signature, signer_id)
        self._ensure_keypair(signer_id)
        return bool(self.spx.verify(message_to_bytes(message), signature, self.public_keys[signer_id]))

    def get_name(self) -> str:
        if self._fallback is not None:
            return self._fallback.get_name()
        return "slh_dsa_sphincsplus"

    def get_signature_size(self) -> int:
        if self._fallback is not None:
            return self._fallback.get_signature_size()
        return self._last_signature_size

    def get_public_key_size(self) -> int:
        if self._fallback is not None:
            return self._fallback.get_public_key_size()
        return int(self.spx.crypto_sign_PUBLICKEYBYTES)

    def get_private_key_size(self) -> int:
        if self._fallback is not None:
            return self._fallback.get_private_key_size()
        return int(self.spx.crypto_sign_SECRETKEYBYTES)

    def get_info(self) -> BackendInfo:
        if self._fallback is not None:
            return self._fallback.get_info()
        return BackendInfo(
            name=self.get_name(),
            parameter_set=self.parameter_module.replace("pyspx.", "SPHINCS+-"),
            implementation="pyspx reference-code bindings",
            language="C reference code via Python CFFI",
            signature_size=self.get_signature_size(),
            public_key_size=self.get_public_key_size(),
            conformance_status=(
                "PySPX SPHINCS+ submission parameter set; FIPS 205 conformance not established"
            ),
        )
