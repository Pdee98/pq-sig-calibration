from calibration.backends.liboqs_ctypes import LibOQSStateless
from src.crypto.liboqs_stateful_ctypes import LibOQSStatefulSigner

STATEFUL = ["XMSS-SHA2_10_256", "XMSSMT-SHA2_20/2_256", "LMS_SHA256_H10_W4", "LMS_SHA256_H10_W4_H10_W4"]
STATELESS = ["Falcon-512", "Falcon-1024"]

for name in STATEFUL:
    with LibOQSStatefulSigner(name) as backend:
        print(f"{name}\tpublic_key={backend.public_key_size}\tsignature={backend.signature_size}\tstateful")
for name in STATELESS:
    backend = LibOQSStateless(name)
    print(f"{name}\tpublic_key={backend.public_key_size}\tsignature_max={backend.signature_size}\tstateless")
    backend.close()
