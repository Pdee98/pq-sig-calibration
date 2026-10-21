import json
import unittest
from pathlib import Path

from src.crypto.liboqs_stateful_ctypes import LibOQSStatefulSigner
from src.crypto.lms_backend import LMSBackend


class CompiledInteropTests(unittest.TestCase):
    @staticmethod
    def _rsp(name):
        values = {}
        for line in (Path(__file__).parent / "fixtures" / name).read_text(encoding="ascii").splitlines():
            if " = " in line:
                key, value = line.split(" = ", 1)
                if key in {"pk", "msg", "sm"}: values[key] = bytes.fromhex(value)
        return values

    def test_lms_hss_l1_round_trip_both_directions(self):
        message = b"portable-lms-interoperability"
        local = LMSBackend(); local.prepare_signer(0)
        with LibOQSStatefulSigner("LMS_SHA256_H10_W4") as compiled:
            compiled_pk = compiled.keygen()
            local_signature = local.sign(message, 0)
            self.assertTrue(compiled.verify(message, b"\0\0\0\0" + local_signature,
                                            b"\0\0\0\1" + local.get_public_key_bytes(0)))
            compiled_signature = compiled.sign(message)
            self.assertTrue(local.verify_with_public_key(message, compiled_signature[4:], compiled_pk[4:]))

    def test_xmss_kat_registry_is_pinned(self):
        kat = Path("third_party/kat/kats.json")
        data = json.loads(kat.read_text(encoding="utf-8"))
        self.assertEqual(data["XMSS-SHA2_10_256"],
                         "7acc06cc456a087456f937d07c7acae2ffeee517cf71b1693adc916f638df388")

    def test_liboqs_stateful_kat_vectors_verify(self):
        for mechanism, fixture in (("XMSS-SHA2_10_256", "XMSS-SHA2_10_256.rsp"),
                                   ("LMS_SHA256_H10_W4", "LMS_SHA256_H10_W4.rsp")):
            with self.subTest(mechanism=mechanism):
                vector = self._rsp(fixture)
                with LibOQSStatefulSigner(mechanism) as backend:
                    self.assertTrue(backend.verify(vector["msg"], vector["sm"], vector["pk"]))


if __name__ == "__main__":
    unittest.main()
