import hashlib
import math
import os


def u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def prf(seed: bytes, *parts: bytes) -> bytes:
    return sha256(seed + b"".join(parts))


def random_bytes(length: int) -> bytes:
    return os.urandom(length)


def base_w(data: bytes, out_len: int, w: int) -> list[int]:
    if w < 2 or w > 256 or w & (w - 1):
        raise ValueError("base_w requires a power-of-two base between 2 and 256")
    log_w = int(math.log2(w))
    total = int.from_bytes(data, "big")
    bits = len(data) * 8
    values = []
    for i in range(out_len):
        shift = bits - log_w * (i + 1)
        if shift >= 0:
            values.append((total >> shift) & (w - 1))
        else:
            values.append(0)
    return values


def wots_lengths(n: int, w: int) -> tuple[int, int, int]:
    log_w = int(math.log2(w))
    len_1 = math.ceil((8 * n) / log_w)
    len_2 = math.floor(math.log(len_1 * (w - 1), w)) + 1
    return len_1, len_2, len_1 + len_2


def lmots_parameters(n: int, w_bits: int) -> tuple[int, int, int, int, int, int]:
    """Return RFC 8554 LM-OTS parameters for supported Winternitz widths.

    The RFC names W1/W2/W4/W8 use w as the number of bits per base-2^w
    digit, not the numeric digit base itself.
    """
    table = {
        (32, 1): (1, 265, 7, 8516),
        (32, 2): (2, 133, 6, 4292),
        (32, 4): (3, 67, 4, 2180),
        (32, 8): (4, 34, 0, 1124),
    }
    try:
        typecode, p, ls, sig_len = table[(n, w_bits)]
    except KeyError as exc:
        raise ValueError(f"unsupported RFC 8554 LMOTS parameters: n={n}, w={w_bits}") from exc

    u = math.ceil((8 * n) / w_bits)
    v = p - u
    return typecode, u, v, p, ls, sig_len


def lmots_checksum_digits(msg_digits: list[int], v: int, w_bits: int, ls: int) -> list[int]:
    base = 1 << w_bits
    checksum = sum(base - 1 - value for value in msg_digits)
    checksum_bytes = (checksum << ls).to_bytes(2, "big")
    return base_w(checksum_bytes, v, base)


def checksum_digits(msg_digits: list[int], len_2: int, w: int) -> list[int]:
    checksum = sum(w - 1 - value for value in msg_digits)
    log_w = int(math.log2(w))
    checksum_bytes_len = math.ceil((len_2 * log_w) / 8)
    checksum_bytes = checksum.to_bytes(checksum_bytes_len, "big")
    return base_w(checksum_bytes, len_2, w)
