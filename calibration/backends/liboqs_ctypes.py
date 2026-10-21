from __future__ import annotations

import ctypes
import os
from pathlib import Path


class OQSError(RuntimeError):
    pass


class _Sig(ctypes.Structure):
    _fields_ = [("method_name", ctypes.c_char_p), ("alg_version", ctypes.c_char_p),
                ("claimed_nist_level", ctypes.c_uint8), ("euf_cma", ctypes.c_bool),
                ("length_public_key", ctypes.c_size_t), ("length_secret_key", ctypes.c_size_t),
                ("length_signature", ctypes.c_size_t)]


def load_oqs() -> ctypes.CDLL:
    prefix = Path(os.environ.get("OQS_INSTALL_PATH", "third_party/install"))
    path = next((p for p in (prefix / "lib64/liboqs.so", prefix / "lib/liboqs.so") if p.is_file()), None)
    if path is None:
        raise OQSError("Local liboqs shared library not found; source third_party/env.sh.")
    lib = ctypes.CDLL(str(path))
    lib.OQS_SIG_new.argtypes = [ctypes.c_char_p]; lib.OQS_SIG_new.restype = ctypes.POINTER(_Sig)
    lib.OQS_SIG_free.argtypes = [ctypes.POINTER(_Sig)]
    lib.OQS_SIG_keypair.argtypes = [ctypes.POINTER(_Sig), ctypes.c_void_p, ctypes.c_void_p]
    lib.OQS_SIG_sign.argtypes = [ctypes.POINTER(_Sig), ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    lib.OQS_SIG_verify.argtypes = [ctypes.POINTER(_Sig), ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    return lib


class LibOQSStateless:
    def __init__(self, mechanism: str):
        self.lib = load_oqs(); self.mechanism = mechanism
        self.sig = self.lib.OQS_SIG_new(mechanism.encode())
        if not self.sig: raise OQSError("Requested liboqs mechanism is unavailable.")
        d = self.sig.contents
        self.public_key_size, self.secret_key_size, self.signature_size = map(int, (d.length_public_key, d.length_secret_key, d.length_signature))
        self.public_key = b""; self.secret_key = b""

    def keygen(self) -> bytes:
        pk = (ctypes.c_ubyte * self.public_key_size)(); sk = (ctypes.c_ubyte * self.secret_key_size)()
        if self.lib.OQS_SIG_keypair(self.sig, pk, sk): raise OQSError("liboqs key generation failed.")
        self.public_key, self.secret_key = bytes(pk), bytes(sk); return self.public_key

    def sign(self, message: bytes) -> bytes:
        out = (ctypes.c_ubyte * self.signature_size)(); n = ctypes.c_size_t(self.signature_size)
        if self.lib.OQS_SIG_sign(self.sig, out, ctypes.byref(n), message, len(message), self.secret_key): raise OQSError("liboqs signing failed.")
        return bytes(out[:n.value])

    def verify(self, message: bytes, signature: bytes) -> bool:
        return self.lib.OQS_SIG_verify(self.sig, message, len(message), signature, len(signature), self.public_key) == 0

    def close(self):
        if self.sig: self.lib.OQS_SIG_free(self.sig); self.sig = None
