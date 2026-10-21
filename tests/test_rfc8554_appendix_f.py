import hashlib
import unittest
import importlib.util

from src.crypto.classical_baseline import ClassicalBaselineBackend
from src.crypto.hash_utils import base_w, lmots_checksum_digits, lmots_parameters, wots_lengths
from src.crypto.lms_backend import LMSBackend
from src.crypto.slh_dsa_backend import SLHDSABackend
from src.crypto.xmss_backend import XMSSBackend


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class Phase1CryptoParameterTests(unittest.TestCase):
    def test_rfc8554_lmots_parameter_table_for_n32(self):
        # RFC 8554 Appendix B/Table 6 and Section 4.1 parameter identifiers.
        expected = {
            1: (0x00000001, 256, 9, 265, 7, 8516),
            2: (0x00000002, 128, 5, 133, 6, 4292),
            4: (0x00000003, 64, 3, 67, 4, 2180),
            8: (0x00000004, 32, 2, 34, 0, 1124),
        }
        for w_bits, params in expected.items():
            with self.subTest(w_bits=w_bits):
                self.assertEqual(lmots_parameters(32, w_bits), params)

    def test_lms_signature_size_formula_for_supported_lmots_widths(self):
        # RFC 8554 LMS signature size: 12 + n * (p + 1) + m * h.
        expected_h10_sizes = {
            1: 8844,
            2: 4620,
            4: 2508,
            8: 1452,
        }
        for w_bits, expected_size in expected_h10_sizes.items():
            with self.subTest(w_bits=w_bits):
                backend = LMSBackend(height=10, n=32, w=w_bits)
                self.assertEqual(backend._signature_size(), expected_size)
                self.assertEqual(backend.get_info().signature_size, expected_size)

        self.assertNotEqual(LMSBackend(height=10, n=32, w=4)._signature_size(), 4620)
        self.assertEqual(LMSBackend(height=10, n=32, w=4).p, 67)

    def test_lms_corrected_w4_sign_verify_size(self):
        backend = LMSBackend(height=5, n=32, w=4)
        message = b"phase 1 lms sanity"
        signature = backend.sign(message, signer_id=0)
        self.assertEqual(len(signature), 2348)
        self.assertTrue(backend.verify(message, signature, signer_id=0))
        self.assertFalse(backend.verify(message + b" tampered", signature, signer_id=0))

    def test_rfc8554_appendix_f_test_case_1_first_lms_signature(self):
        # Verifies RFC 8554 Appendix F Test Case 1, first LMS signature.
        upper_public_key_k = bytes.fromhex(
            "50650e3b31fe4a773ea29a07f09cf2ea"
            "30e579f0df58ef8e298da0434cb2b878"
        )
        upper_public_key_i = bytes.fromhex("61a5d57d37f5e46bfb7520806b07a1b8")
        lower_lms_public_key = bytes.fromhex(
            "00000005"
            "00000004"
            "d2f14ff6346af964569f7d6cb880a1b6"
            "6c5004917da6eafe4d9ef6c6407b3db0"
            "e5485b122d9ebe15cda93cfec582d7ab"
        )
        q = 5
        c = bytes.fromhex(
            "d32b56671d7eb98833c49b433c272586"
            "bc4a1c8a8970528ffa04b966f9426eb9"
        )
        y_values = [
            bytes.fromhex(value)
            for value in [
                "965a25bfd37f196b9073f3d4a232feb69128ec45146f86292f9dff9610a7bf95",
                "a64c7f60f6261a62043f86c70324b7707f5b4a8a6e19c114c7be866d488778a0",
                "e05fd5c6509a6e61d559cf1a77a970de927d60c70d3de31a7fa0100994e162a2",
                "582e8ff1b10cd99d4e8e413ef469559f7d7ed12c838342f9b9c96b83a4943d16",
                "81d84b15357ff48ca579f19f5e71f18466f2bbef4bf660c2518eb20de2f66e3b",
                "14784269d7d876f5d35d3fbfc7039a462c716bb9f6891a7f41ad133e9e1f6d95",
                "60b960e7777c52f060492f2d7c660e1471e07e72655562035abc9a701b473ecb",
                "c3943c6b9c4f2405a3cb8bf8a691ca51d3f6ad2f428bab6f3a30f55dd9625563",
                "f0a75ee390e385e3ae0b906961ecf41ae073a0590c2eb6204f44831c26dd768c",
                "35b167b28ce8dc988a3748255230cef99ebf14e730632f27414489808afab1d1",
                "e783ed04516de012498682212b07810579b250365941bcc98142da13609e9768",
                "aaf65de7620dabec29eb82a17fde35af15ad238c73f81bdb8dec2fc0e7f93270",
                "1099762b37f43c4a3c20010a3d72e2f606be108d310e639f09ce7286800d9ef8",
                "a1a40281cc5a7ea98d2adc7c7400c2fe5a101552df4e3cccfd0cbf2ddf5dc677",
                "9cbbc68fee0c3efe4ec22b83a2caa3e48e0809a0a750b73ccdcf3c79e6580c15",
                "4f8a58f7f24335eec5c5eb5e0cf01dcf4439424095fceb077f66ded5bec73b27",
                "c5b9f64a2a9af2f07c05e99e5cf80f00252e39db32f6c19674f190c9fbc506d8",
                "26857713afd2ca6bb85cd8c107347552f30575a5417816ab4db3f603f2df56fb",
                "c413e7d0acd8bdd81352b2471fc1bc4f1ef296fea1220403466b1afe78b94f7e",
                "cf7cc62fb92be14f18c2192384ebceaf8801afdf947f698ce9c6ceb696ed70e9",
                "e87b0144417e8d7baf25eb5f70f09f016fc925b4db048ab8d8cb2a661ce3b57a",
                "da67571f5dd546fc22cb1f97e0ebd1a65926b1234fd04f171cf469c76b884cf3",
                "115cce6f792cc84e36da58960c5f1d760f32c12faef477e94c92eb75625b6a37",
                "1efc72d60ca5e908b3a7dd69fef0249150e3eebdfed39cbdc3ce9704882a2072",
                "c75e13527b7a581a556168783dc1e97545e31865ddc46b3c957835da252bb732",
                "8d3ee2062445dfb85ef8c35f8e1f3371af34023cef626e0af1e0bc017351aae2",
                "ab8f5c612ead0b729a1d059d02bfe18efa971b7300e882360a93b025ff97e9e0",
                "eec0f3f3f13039a17f88b0cf808f488431606cb13f9241f40f44e537d302c64a",
                "4f1f4ab949b9feefadcb71ab50ef27d6d6ca8510f150c85fb525bf25703df720",
                "9b6066f09c37280d59128d2f0f637c7d7d7fad4ed1c1ea04e628d221e3d8db77",
                "b7c878c9411cafc5071a34a00f4cf07738912753dfce48f07576f0d4f94f42c6",
                "d76f7ce973e9367095ba7e9a3649b7f461d9f9ac1332a4d1044c96aefee67676",
                "401b64457c54d65fef6500c59cdfb69af7b6dddfcb0f086278dd8ad0686078df",
                "b0f3f79cd893d314168648499898fbc0ced5f95b74e8ff14d735cdea968bee74",
            ]
        ]
        path = [
            bytes.fromhex(value)
            for value in [
                "d8b8112f9200a5e50c4a262165bd342cd800b8496810bc716277435ac376728d",
                "129ac6eda839a6f357b5a04387c5ce97382a78f2a4372917eefcbf93f63bb591",
                "12f5dbe400bd49e4501e859f885bf0736e90a509b30a26bfac8c17b5991c157e",
                "b5971115aa39efd8d564a6b90282c3168af2d30ef89d51bf14654510a12b8a14",
                "4cca1848cf7da59cc2b3d9d0692dd2a20ba3863480e25b1b85ee860c62bf5136",
            ]
        ]

        self.assertEqual(len(y_values), 34)
        self.assertEqual(4 + 32 + 34 * 32, 1124)
        self.assertEqual(4 + 1124 + 4 + 5 * 32, 1292)

        digest = _h(upper_public_key_i + _u32(q) + _u16(0x8181) + c + lower_lms_public_key)
        msg_digits = base_w(digest, 32, 256)
        digits = msg_digits + lmots_checksum_digits(msg_digits, 2, 8, 0)
        z_values = []
        for i, y in enumerate(y_values):
            value = y
            for j in range(digits[i], 256 - 1):
                value = _h(upper_public_key_i + _u32(q) + _u16(i) + bytes([j]) + value)
            z_values.append(value)
        ots_public_key = _h(upper_public_key_i + _u32(q) + _u16(0x8080) + b"".join(z_values))
        node_num = (1 << 5) + q
        node = _h(upper_public_key_i + _u32(node_num) + _u16(0x8282) + ots_public_key)
        for sibling in path:
            parent = node_num // 2
            if node_num % 2 == 0:
                node = _h(upper_public_key_i + _u32(parent) + _u16(0x8383) + node + sibling)
            else:
                node = _h(upper_public_key_i + _u32(parent) + _u16(0x8383) + sibling + node)
            node_num = parent

        self.assertEqual(node, upper_public_key_k)

        public_key = _u32(0x00000005) + _u32(0x00000004) + upper_public_key_i + upper_public_key_k
        lmots_signature = _u32(0x00000004) + c + b"".join(y_values)
        signature = _u32(q) + lmots_signature + _u32(0x00000005) + b"".join(path)
        backend = LMSBackend(height=5, n=32, w=8)

        self.assertTrue(backend.verify_with_public_key(lower_lms_public_key, signature, public_key))
        self.assertFalse(backend.verify_with_public_key(lower_lms_public_key + b"!", signature, public_key))

        tampered_signature = bytearray(signature)
        tampered_signature[-1] ^= 0x01
        self.assertFalse(backend.verify_with_public_key(lower_lms_public_key, bytes(tampered_signature), public_key))
        self.assertFalse(backend.verify_with_public_key(lower_lms_public_key, signature[:-1], public_key))
        self.assertFalse(backend.verify_with_public_key(lower_lms_public_key, signature + b"\x00", public_key))

        unsupported_lmots_type_signature = bytearray(signature)
        unsupported_lmots_type_signature[7] = 0xFF
        self.assertFalse(
            backend.verify_with_public_key(lower_lms_public_key, bytes(unsupported_lmots_type_signature), public_key)
        )

        unsupported_lms_type_signature = bytearray(signature)
        lms_type_offset = 4 + len(lmots_signature)
        unsupported_lms_type_signature[lms_type_offset + 3] = 0xFF
        self.assertFalse(
            backend.verify_with_public_key(lower_lms_public_key, bytes(unsupported_lms_type_signature), public_key)
        )

        unsupported_lmots_type_public_key = bytearray(public_key)
        unsupported_lmots_type_public_key[7] = 0xFF
        self.assertFalse(
            backend.verify_with_public_key(lower_lms_public_key, signature, bytes(unsupported_lmots_type_public_key))
        )

        unsupported_lms_type_public_key = bytearray(public_key)
        unsupported_lms_type_public_key[3] = 0xFF
        self.assertFalse(
            backend.verify_with_public_key(lower_lms_public_key, signature, bytes(unsupported_lms_type_public_key))
        )

    def test_xmss_wots_length_and_sizes(self):
        self.assertEqual(wots_lengths(32, 16), (64, 3, 67))
        backend = XMSSBackend(height=10, n=32, w=16)
        self.assertEqual(backend._signature_size(), 2500)
        self.assertEqual(backend.get_public_key_size(), 68)
        info = backend.get_info()
        self.assertEqual(info.signature_size, 2500)
        self.assertEqual(info.public_key_size, 68)

    def test_lightweight_backend_sanity_without_simulation(self):
        backends = [
            ClassicalBaselineBackend(),
            XMSSBackend(height=4),
            LMSBackend(height=5, w=4),
        ]
        if _module_available("pyspx.sha2_128s"):
            backends.append(SLHDSABackend(parameter_module="pyspx.sha2_128s"))
        else:
            backends.append(SLHDSABackend())
        message = b"phase 1 backend sanity"
        for backend in backends:
            with self.subTest(backend=backend.get_name()):
                backend.prepare_signer(0)
                signature = backend.sign(message, 0)
                self.assertEqual(len(signature), backend.get_signature_size())
                self.assertTrue(backend.verify(message, signature, 0))
                self.assertFalse(backend.verify(message + b"!", signature, 0))
                info = backend.get_info()
                self.assertIsNotNone(info.signature_size)
                self.assertIsNotNone(info.public_key_size)
                self.assertTrue(info.conformance_status)

def _module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


if __name__ == "__main__":
    unittest.main()
