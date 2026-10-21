from dataclasses import dataclass

from src.crypto.hash_utils import base_w, checksum_digits, prf, sha256, u32, wots_lengths


@dataclass(frozen=True)
class WOTSPlusParams:
    n: int = 32
    w: int = 16

    @property
    def len_1(self) -> int:
        return wots_lengths(self.n, self.w)[0]

    @property
    def len_2(self) -> int:
        return wots_lengths(self.n, self.w)[1]

    @property
    def length(self) -> int:
        return wots_lengths(self.n, self.w)[2]


class WOTSPlus:
    """WOTS+ core used by XMSS.

    The structure follows RFC 8391, Sections 3.1.2 through 3.1.6: private
    string generation, base-w message/checksum expansion, chaining, signing,
    and deriving a public key candidate from a signature.
    """

    def __init__(self, params: WOTSPlusParams):
        self.params = params

    def _secret_element(self, sk_seed: bytes, leaf_index: int, chain_index: int) -> bytes:
        return prf(sk_seed, b"WOTS-SK", u32(leaf_index), u32(chain_index))

    def _chain(
        self,
        value: bytes,
        start: int,
        steps: int,
        pub_seed: bytes,
        leaf_index: int,
        chain_index: int,
    ) -> bytes:
        result = value
        for step in range(start, start + steps):
            key = prf(pub_seed, b"WOTS-KEY", u32(leaf_index), u32(chain_index), u32(step))
            bitmask = prf(pub_seed, b"WOTS-MASK", u32(leaf_index), u32(chain_index), u32(step))
            result = sha256(key + bytes(a ^ b for a, b in zip(result, bitmask)))
        return result

    def _message_digits(self, message_digest: bytes) -> list[int]:
        msg = base_w(message_digest, self.params.len_1, self.params.w)
        return msg + checksum_digits(msg, self.params.len_2, self.params.w)

    def public_key(self, sk_seed: bytes, pub_seed: bytes, leaf_index: int) -> list[bytes]:
        return [
            self._chain(
                self._secret_element(sk_seed, leaf_index, i),
                0,
                self.params.w - 1,
                pub_seed,
                leaf_index,
                i,
            )
            for i in range(self.params.length)
        ]

    def sign(self, message_digest: bytes, sk_seed: bytes, pub_seed: bytes, leaf_index: int) -> list[bytes]:
        digits = self._message_digits(message_digest)
        return [
            self._chain(
                self._secret_element(sk_seed, leaf_index, i),
                0,
                digits[i],
                pub_seed,
                leaf_index,
                i,
            )
            for i in range(self.params.length)
        ]

    def pk_from_signature(
        self,
        signature: list[bytes],
        message_digest: bytes,
        pub_seed: bytes,
        leaf_index: int,
    ) -> list[bytes]:
        digits = self._message_digits(message_digest)
        return [
            self._chain(
                signature[i],
                digits[i],
                self.params.w - 1 - digits[i],
                pub_seed,
                leaf_index,
                i,
            )
            for i in range(self.params.length)
        ]


def l_tree(wots_pk: list[bytes]) -> bytes:
    nodes = list(wots_pk)
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes) - 1, 2):
            next_level.append(sha256(b"LTREE" + nodes[i] + nodes[i + 1]))
        if len(nodes) % 2 == 1:
            next_level.append(nodes[-1])
        nodes = next_level
    return nodes[0]
