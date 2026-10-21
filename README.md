# Portable signature calibration

This public-safe repository reproduces the Revision R1 Step D **REAL-CRYPTO**
calibration protocol on x86-64 and AArch64 Linux. It builds OpenSSL 3.5.5 and
liboqs 0.16.0 in `./third_party/install`; no system installation is performed.

## Protocol

Each GitHub Actions matrix job is one independent session (`rep=1..3`) with 10
key generations, 300 valid signatures, 300 valid verifications, invalid
verification probes, and 300 durable state writes per stateful backend. Project
XMSS/LMS include both the historical index window 20--69 and lifetime sampling
uniformly without replacement over 0--1023. Messages are deterministic SHA-256
derivations from backend/session/sample identifiers. An untimed key generation
warms the sign/verify path. Stateful signatures are never reused as secrets or
published as fixtures.

The timed-region parity file separately compares the integrated calibration
call path with a pre-loaded-key, pre-serialized-message primitive call. It uses
2,000 verifications and 200 signatures per backend; slow SLH-DSA `s` signing
sets use 10 signatures and record that count in the CSV.

## Local run

```bash
bash scripts/build_deps.sh
source third_party/env.sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
PYTHONPATH=. python -m unittest discover -s tests -v
PYTHONPATH=. python scripts/run_calibration.py --output outputs/local-rep1 --session-index 0
```

Use `--quick` for an end-to-end plumbing check. Outputs are `raw_samples.csv`,
`calibration_summary.csv`, `timed_region_parity.csv`, `environment.json`,
`calibration_protocol.json`, and `SHA256SUMS`.

## Dependency provenance

- OpenSSL 3.5.5 release archive SHA-256:
  `b28c91532a8b65a1f983b4c28b7488174e4a01008e29ce8e69bd789f28bc2a89`.
- liboqs 0.16.0, commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`,
  release archive SHA-256:
  `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae`.
- liboqs is Release-built with `OQS_USE_OPENSSL=ON`, Falcon, XMSS/XMSS-MT,
  LMS/HSS, and the hazardous experimental stateful key/sign-generation option.

OpenSSL algorithm availability is evidence of an implementation, not proof of
FIPS-validated module certification. Cross-host timings must not be pooled as
independent operation samples from one hardware population.

## Expected runtime

Reference Step D evidence took about 61 minutes per session on x86 WSL. The
dependency build and parity measurements bring the expected x86 job to roughly
2 hours. A conservative 2x--2.25x ARM allowance gives 4--4.5 hours, below the
350-minute workflow timeout. Runtime is host-dependent and this is not an upper
bound.
