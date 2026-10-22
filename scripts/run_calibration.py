from __future__ import annotations

import argparse
import ctypes
import csv
import gc
import hashlib
import json
import math
import os
import platform
import random
import statistics
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.crypto.liboqs_stateful_ctypes import LibOQSStatefulSigner
from calibration.backends.liboqs_ctypes import LibOQSStateless
from src.crypto.lms_backend import LMSBackend
from src.crypto.openssl_evp_signature import OpenSSLEVPBackend, PARAMETERS
from src.crypto.xmss_backend import XMSSBackend


STATEFUL = {
    "liboqs_xmss_sha2_10_256": "XMSS-SHA2_10_256",
    "liboqs_xmssmt_sha2_20_2_256": "XMSSMT-SHA2_20/2_256",
    "liboqs_lms_h10_w4": "LMS_SHA256_H10_W4",
    "liboqs_hss_h10_w4_h10_w4": "LMS_SHA256_H10_W4_H10_W4",
}
OPENSSL = {algorithm.lower().replace("-", "_"): algorithm for algorithm in PARAMETERS}
FALCON = {"liboqs_falcon_512": "Falcon-512", "liboqs_falcon_1024": "Falcon-1024"}
PROJECT = {
    "project_xmss_sha2_10_256_accepted": (XMSSBackend, "accepted"),
    "project_xmss_sha2_10_256_lifetime": (XMSSBackend, "lifetime"),
    "project_lms_h10_w4_accepted": (LMSBackend, "accepted"),
    "project_lms_h10_w4_lifetime": (LMSBackend, "lifetime"),
}
ED25519 = {"ed25519_cryptography": "Ed25519"}


class _Ed25519:
    signature_size = 64
    public_key_size = 32
    def keygen(self):
        self.sk = Ed25519PrivateKey.generate(); self.pk = self.sk.public_key()
        return self.pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
    def sign(self, message): return self.sk.sign(message)
    def verify(self, message, signature):
        try: self.pk.verify(signature, message); return True
        except Exception: return False
    def close(self): pass


class _NoOpBackend:
    def noop(self):
        return None


def _liboqs_library_path() -> Path:
    prefix = os.environ.get("OQS_INSTALL_PATH")
    candidates = []
    if prefix:
        candidates.extend((Path(prefix) / "lib/liboqs.so", Path(prefix) / "lib64/liboqs.so"))
    candidates.append(Path(__file__).resolve().parents[1] / "third_party/install/lib/liboqs.so")
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise RuntimeError("The project-local liboqs shared library is unavailable.")


def _r2_probe(output: Path, session: int, sample_count: int, overhead_count: int) -> None:
    rows = []
    backend = _Ed25519()
    public_key = backend.keygen()
    message = _message("ed25519_cryptography", session, 0)
    signature = backend.sign(message)
    for index in range(sample_count):
        flipped = bytearray(signature)
        flipped[index % len(flipped)] ^= 1
        rejected, duration = _time_rejection(backend.verify, message, bytes(flipped))
        rows.append(_row("ed25519_cryptography", session, "verify_invalid", index, duration,
                         len(signature), len(public_key), rejected, "single_bit_flip"))
        rejected, duration = _time_rejection(backend.verify, message, os.urandom(len(signature)))
        rows.append(_row("ed25519_cryptography", session, "verify_invalid", index, duration,
                         len(signature), len(public_key), rejected, "random_bytes"))
    backend.close()
    _append_raw_rows(output / "raw_samples.csv", rows)

    noop = _NoOpBackend()
    library = ctypes.CDLL(str(_liboqs_library_path()))
    oqs_version = library.OQS_version
    oqs_version.argtypes = []
    oqs_version.restype = ctypes.c_char_p
    overhead_rows = []
    for operation, function in (("python_noop_method", noop.noop), ("ctypes_oqs_version", oqs_version)):
        for index in range(overhead_count):
            _, duration = _time_call(function)
            overhead_rows.append({
                "evidence_label": "REAL-CRYPTO",
                "operation": operation,
                "sample_index": index,
                "duration_ns": duration,
                "timer": "time.perf_counter_ns",
                "timed_region": "one Python method call" if operation == "python_noop_method"
                                else "one ctypes call to OQS_version in the loaded project-local liboqs",
            })
    _write_csv(output / "overhead_probe.csv", overhead_rows)


def _calibrate_simple(label, factory, session, counts, rows):
    keygen_count, sample_count = counts
    for index in range(keygen_count):
        backend = factory(); public_key, duration = _time_call(backend.keygen)
        rows.append(_row(label, session, "keygen", index, duration, backend.signature_size, len(public_key))); backend.close()
    backend = factory(); public_key = backend.keygen(); signatures = []
    for index in range(sample_count):
        message = _message(label, session, index); signature, duration = _time_call(backend.sign, message)
        signatures.append((message, signature)); rows.append(_row(label, session, "sign", index, duration, len(signature), len(public_key)))
    for index, (message, signature) in enumerate(signatures):
        accepted, duration = _time_call(backend.verify, message, signature)
        rows.append(_row(label, session, "verify", index, duration, len(signature), len(public_key), accepted))
        flipped = bytearray(signature)
        flipped[index % len(flipped)] ^= 1
        rejected, duration = _time_rejection(backend.verify, message, bytes(flipped))
        rows.append(_row(label, session, "verify_invalid", index, duration, len(signature),
                         len(public_key), rejected, "single_bit_flip"))
        rejected, duration = _time_rejection(backend.verify, message, os.urandom(len(signature)))
        rows.append(_row(label, session, "verify_invalid", index, duration, len(signature),
                         len(public_key), rejected, "random_bytes"))
    backend.close()


def _message(label: str, session: int, index: int) -> bytes:
    return hashlib.sha256(f"revision-r1:{label}:{session}:{index}".encode("ascii")).digest()


def _time_call(function, *args):
    start = time.perf_counter_ns()
    value = function(*args)
    return value, time.perf_counter_ns() - start


def _time_rejection(function, *args):
    start = time.perf_counter_ns()
    try:
        accepted = function(*args)
        return not accepted, time.perf_counter_ns() - start
    except Exception:
        return True, time.perf_counter_ns() - start


def _row(label, session, operation, index, duration, signature_size, public_key_size, success=True, variant="valid"):
    return {
        "evidence_label": "REAL-CRYPTO",
        "backend": label,
        "session": session,
        "operation": operation,
        "variant": variant,
        "sample_index": index,
        "duration_ns": duration,
        "signature_size_bytes": signature_size,
        "public_key_size_bytes": public_key_size,
        "success": str(bool(success)).lower(),
    }


def _calibrate_stateful(label, mechanism, session, counts, rows):
    keygen_count, sample_count = counts
    public_size = signature_size = None
    for index in range(keygen_count):
        with LibOQSStatefulSigner(mechanism) as backend:
            public_key, duration = _time_call(backend.keygen)
            public_size, signature_size = len(public_key), backend.signature_size
            rows.append(_row(label, session, "keygen", index, duration, signature_size, public_size))
    with LibOQSStatefulSigner(mechanism) as backend:
        public_key = backend.keygen()
        signatures = []
        for index in range(sample_count):
            message = _message(label, session, index)
            signature, duration = _time_call(backend.sign, message)
            signatures.append((message, signature))
            rows.append(_row(label, session, "sign", index, duration, len(signature), len(public_key)))
        for index, (message, signature) in enumerate(signatures):
            accepted, duration = _time_call(backend.verify, message, signature)
            rows.append(_row(label, session, "verify", index, duration, len(signature), len(public_key), accepted))
            flipped = bytearray(signature)
            flipped[len(flipped) // 2] ^= 1
            rejected, duration = _time_call(backend.verify, message, bytes(flipped))
            rows.append(_row(label, session, "verify_invalid", index, duration, len(signature), len(public_key), not rejected, "single_bit_flip"))
            random_signature = os.urandom(len(signature))
            rejected, duration = _time_call(backend.verify, message, random_signature)
            rows.append(_row(label, session, "verify_invalid", index, duration, len(signature), len(public_key), not rejected, "random_bytes"))


def _calibrate_openssl(label, algorithm, session, counts, rows):
    keygen_count, sample_count = counts
    params = PARAMETERS[algorithm]
    for index in range(keygen_count):
        backend = OpenSSLEVPBackend(algorithm)
        _, duration = _time_call(backend.keygen)
        rows.append(_row(label, session, "keygen", index, duration, params.signature_size, params.public_key_size))
        backend.close()
    backend = OpenSSLEVPBackend(algorithm)
    public_key = backend.keygen()
    signatures = []
    for index in range(sample_count):
        message = _message(label, session, index)
        signature, duration = _time_call(backend.sign, message)
        signatures.append((message, signature))
        rows.append(_row(label, session, "sign", index, duration, len(signature), len(public_key)))
    for index, (message, signature) in enumerate(signatures):
        accepted, duration = _time_call(backend.verify, message, signature)
        rows.append(_row(label, session, "verify", index, duration, len(signature), len(public_key), accepted))
        flipped = bytearray(signature); flipped[len(flipped) // 2] ^= 1
        rejected, duration = _time_call(backend.verify, message, bytes(flipped))
        rows.append(_row(label, session, "verify_invalid", index, duration, len(signature), len(public_key), not rejected, "single_bit_flip"))
        rejected, duration = _time_call(backend.verify, message, os.urandom(len(signature)))
        rows.append(_row(label, session, "verify_invalid", index, duration, len(signature), len(public_key), not rejected, "random_bytes"))
    backend.close()


def _calibrate_falcon(label, mechanism, session, counts, rows):
    keygen_count, sample_count = counts
    public_size = signature_capacity = None
    for index in range(keygen_count):
        backend = LibOQSStateless(mechanism)
        public_key, duration = _time_call(backend.keygen)
        public_size, signature_capacity = len(public_key), backend.signature_size
        rows.append(_row(label, session, "keygen", index, duration, signature_capacity, public_size))
        backend.close()
    backend = LibOQSStateless(mechanism)
    public_key = backend.keygen()
    signatures = []
    for index in range(sample_count):
        message = _message(label, session, index)
        signature, duration = _time_call(backend.sign, message)
        signatures.append((message, signature))
        rows.append(_row(label, session, "sign", index, duration, len(signature), len(public_key)))
    for index, (message, signature) in enumerate(signatures):
        accepted, duration = _time_call(backend.verify, message, signature)
        rows.append(_row(label, session, "verify", index, duration, len(signature), len(public_key), accepted))
        flipped = bytearray(signature); flipped[len(flipped) // 2] ^= 1
        rejected, duration = _time_rejection(backend.verify, message, bytes(flipped))
        rows.append(_row(label, session, "verify_invalid", index, duration, len(signature), len(public_key), rejected, "single_bit_flip"))
        random_signature = os.urandom(len(signature))
        rejected, duration = _time_rejection(backend.verify, message, random_signature)
        rows.append(_row(label, session, "verify_invalid", index, duration, len(signature), len(public_key), rejected, "random_bytes"))
    backend.close()


def _calibrate_project(label, backend_class, mode, session, counts, rows, seed):
    keygen_count, sample_count = counts
    signature_size = public_size = None
    for index in range(keygen_count):
        backend = backend_class()
        _, duration = _time_call(backend.prepare_signer, 0)
        signature_size, public_size = backend.get_signature_size(), backend.get_public_key_size()
        rows.append(_row(label, session, "keygen", index, duration, signature_size, public_size))
        del backend
        gc.collect()
    backend = backend_class()
    backend.prepare_signer(0)
    rng = random.Random(seed + session)
    indices = (sorted(rng.sample(range(1024), sample_count)) if mode == "lifetime"
               else [20 + (index % 50) for index in range(sample_count)])
    signatures = []
    for sample_index, leaf_index in enumerate(indices):
        if mode == "accepted" and sample_index and sample_index % 50 == 0:
            backend.generate_new_signer(0)
        backend.keypairs[0].next_index = leaf_index
        message = _message(label, session, sample_index)
        signature, duration = _time_call(backend.sign, message, 0)
        signatures.append((message, signature))
        row = _row(label, session, "sign_lifetime" if mode == "lifetime" else "sign", sample_index, duration, len(signature), backend.get_public_key_size())
        row["leaf_index"] = leaf_index
        rows.append(row)
    for index, (message, signature) in enumerate(signatures):
        accepted, duration = _time_call(backend.verify, message, signature, 0)
        rows.append(_row(label, session, "verify", index, duration, len(signature), backend.get_public_key_size(), accepted))
        flipped = bytearray(signature); flipped[len(flipped) // 2] ^= 1
        rejected, duration = _time_call(backend.verify, message, bytes(flipped), 0)
        rows.append(_row(label, session, "verify_invalid", index, duration, len(signature), backend.get_public_key_size(), not rejected, "single_bit_flip"))
        rejected, duration = _time_call(backend.verify, message, os.urandom(len(signature)), 0)
        rows.append(_row(label, session, "verify_invalid", index, duration, len(signature), backend.get_public_key_size(), not rejected, "random_bytes"))


def _durable_persistence(output: Path, rows: list[dict], sample_count: int, labels=None) -> None:
    target_dir = output / "persistence_probe"
    target_dir.mkdir(exist_ok=True)
    selected = labels if labels is not None else (*STATEFUL.keys(), *PROJECT.keys())
    for label in selected:
        target = target_dir / f"{label}.state"
        for index in range(sample_count):
            state = json.dumps({"backend": label, "next_index": index + 1}, sort_keys=True).encode("ascii")
            temporary = target.with_suffix(".tmp")
            start = time.perf_counter_ns()
            with temporary.open("wb") as handle:
                handle.write(state)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
            directory_fd = os.open(target_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            duration = time.perf_counter_ns() - start
            rows.append(_row(label, 0, "state_write_fsync", index, duration, "", ""))


def _parity_adapter(label):
    if label in ED25519:
        backend = _Ed25519(); backend.keygen()
        return backend, backend.sign, backend.verify
    if label in OPENSSL:
        backend = OpenSSLEVPBackend(OPENSSL[label]); backend.keygen()
        return backend, backend.sign, backend.verify
    if label in FALCON:
        backend = LibOQSStateless(FALCON[label]); backend.keygen()
        return backend, backend.sign, backend.verify
    if label in STATEFUL:
        backend = LibOQSStatefulSigner(STATEFUL[label]); backend.keygen()
        return backend, backend.sign, backend.verify
    backend_class, _mode = PROJECT[label]
    backend = backend_class(); backend.prepare_signer(0)
    return backend, lambda m: backend.sign(m, 0), lambda m, s: backend.verify(m, s, 0)


def _timed_region_parity(labels, session, quick=False):
    output = []
    for label in labels:
        backend, sign, verify = _parity_adapter(label)
        fixed = _message(label, session, 999999); signature = sign(fixed)
        verify_count = 3 if quick else 2000
        sign_count = 2 if quick else (10 if any(x in label for x in ("192s", "256s")) else 200)
        for operation, count in (("verify", verify_count), ("sign", sign_count)):
            for region in ("integrated", "bare_primitive"):
                for index in range(count):
                    if operation == "verify":
                        start = time.perf_counter_ns()
                        ok = verify(fixed, signature)
                        duration = time.perf_counter_ns() - start
                    else:
                        start = time.perf_counter_ns()
                        sign(fixed); ok = True; duration = time.perf_counter_ns() - start
                    output.append({"backend": label, "session": session, "operation": operation,
                                   "timed_region": region, "sample_index": index,
                                   "duration_ns": duration, "success": str(bool(ok)).lower(),
                                   "work_inside_region": ("backend method exactly as timed by calibration; key pre-loaded and message pre-serialized" if region == "integrated" else "primitive call with pre-loaded key and pre-serialized message; identical boundary when the ctypes adapter is primitive-thin")})
        if hasattr(backend, "close"): backend.close()
    return output


def _stats(values):
    ordered = sorted(values)
    n = len(ordered)
    return {
        "count": n,
        "mean_ns": statistics.mean(ordered),
        "stdev_ns": statistics.stdev(ordered) if n > 1 else 0,
        "median_ns": statistics.median(ordered),
        "p95_ns": ordered[min(n - 1, math.ceil(0.95 * n) - 1)],
    }


def _summary(rows):
    groups = {}
    for row in rows:
        if row["success"] != "true":
            continue
        key = (row["backend"], row["operation"], row["variant"])
        groups.setdefault(key, []).append(row)
    output = []
    for (backend, operation, variant), items in sorted(groups.items()):
        stats = _stats([int(item["duration_ns"]) for item in items])
        session_means = [statistics.mean(int(item["duration_ns"]) for item in items if int(item["session"]) == session) for session in sorted({int(item["session"]) for item in items})]
        stats.update({
            "evidence_label": "REAL-CRYPTO", "backend": backend, "operation": operation, "variant": variant,
            "between_session_stdev_of_means_ns": statistics.stdev(session_means) if len(session_means) > 1 else 0,
            "signature_size_min": min((int(item["signature_size_bytes"]) for item in items if str(item["signature_size_bytes"])), default=""),
            "signature_size_max": max((int(item["signature_size_bytes"]) for item in items if str(item["signature_size_bytes"])), default=""),
            "public_key_size_bytes": next((item["public_key_size_bytes"] for item in items if str(item["public_key_size_bytes"])), ""),
        })
        output.append(stats)
    return output


def _accepted_samples(path: Path, backend_fragment: str):
    with path.open(newline="", encoding="utf-8") as handle:
        return [int(row["wall_duration_ns"]) for row in csv.DictReader(handle) if backend_fragment in row["backend_label"] and row["operation"] == "sign" and row["included_in_profile"] == "true" and row["success"] == "true"]


def _two_sample(current, accepted):
    mean_a, mean_b = statistics.mean(current), statistics.mean(accepted)
    if len(current) < 2 or len(accepted) < 2:
        return {"welch_t": None, "two_sided_p_normal_approx": None, "cohens_d": None, "current_mean_ns": mean_a, "accepted_mean_ns": mean_b}
    var_a, var_b = statistics.variance(current), statistics.variance(accepted)
    se = math.sqrt(var_a / len(current) + var_b / len(accepted))
    t = (mean_a - mean_b) / se if se else 0.0
    p_normal_approx = math.erfc(abs(t) / math.sqrt(2))
    pooled = math.sqrt(((len(current) - 1) * var_a + (len(accepted) - 1) * var_b) / (len(current) + len(accepted) - 2))
    return {"welch_t": t, "two_sided_p_normal_approx": p_normal_approx, "cohens_d": (mean_a - mean_b) / pooled if pooled else 0.0, "current_mean_ns": mean_a, "accepted_mean_ns": mean_b}


def _environment(started_at, ended_at):
    cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
    flags_line = next((line for line in cpuinfo.splitlines() if line.startswith("flags")), "")
    free = subprocess.run(["free", "-b"], check=True, capture_output=True, text=True).stdout
    import cryptography
    lscpu = subprocess.run(["lscpu"], check=True, capture_output=True, text=True).stdout
    flags = set(flags_line.split(":", 1)[-1].split())
    return {
        "run_start_utc": started_at, "run_end_utc": ended_at,
        "python": platform.python_version(), "cryptography": cryptography.__version__, "platform": platform.platform(),
        "cpu_model": next((line.split(":", 1)[1].strip() for line in cpuinfo.splitlines() if line.startswith("model name")), "unknown"),
        "architecture": platform.machine(), "lscpu": lscpu, "cpuinfo_flags": sorted(flags),
        "sha_ni": "sha_ni" in flags, "sha2": "sha2" in flags, "core_count": os.cpu_count(), "memory": free,
        "kernel": platform.release(), "os": platform.platform(),
        "virtualization_type": next((line.split(":",1)[1].strip() for line in lscpu.splitlines() if line.startswith("Virtualization type:")), "none reported"),
        "runner_name": os.environ.get("RUNNER_NAME", "local"),
        "liboqs_version": "0.16.0", "liboqs_commit": "5a1a854b0dc9f2141bdc771c555ee60c37950183", "liboqs_oqs_use_openssl": True,
        "liboqs_sha2_implementation": "OpenSSL-backed SHA-2/common primitives (OQS_USE_OPENSSL=ON)",
        "openssl_version": subprocess.run(["openssl", "version", "-a"], check=True, capture_output=True, text=True).stdout,
    }


def _write_csv(path, rows):
    fields = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


RAW_FIELDS = [
    "backend", "duration_ns", "evidence_label", "leaf_index", "operation",
    "public_key_size_bytes", "sample_index", "session", "signature_size_bytes",
    "success", "variant",
]


def _append_raw_rows(path, rows):
    new_file = not path.exists()
    with path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=RAW_FIELDS, extrasaction="raise")
        if new_file:
            writer.writeheader()
        writer.writerows(rows)
        handle.flush()
        os.fsync(handle.fileno())


def _write_progress(output, selected, completed, started_at, status="running"):
    payload = {
        "schema_version": "step-d-portable-progress-v1",
        "status": status,
        "selected_backends": selected,
        "completed_backends": completed,
        "completed_count": len(completed),
        "updated_at_utc": datetime.now(UTC).isoformat(),
        "run_start_utc": started_at,
    }
    temporary = output / "progress.json.tmp"
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, output / "progress.json")


def _read_raw_rows(path):
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _sha_manifest(output):
    entries = []
    for path in sorted(p for p in output.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        entries.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(output).as_posix()}")
    (output / "SHA256SUMS").write_text("\n".join(entries) + "\n", encoding="ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sessions", type=int, default=1)
    parser.add_argument("--keygen", type=int, default=10)
    parser.add_argument("--samples", type=int, default=300)
    parser.add_argument("--persistence-samples", type=int, default=300)
    parser.add_argument("--session-index", type=int, default=0)
    parser.add_argument("--backends", default="all", help="Comma-separated backend IDs, 'all', or 'r2_probe'.")
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    started_clock = time.perf_counter(); started_at = datetime.now(UTC).isoformat()
    if args.quick:
        args.keygen, args.samples, args.persistence_samples = 1, 2, 2
    all_labels = [*ED25519, *STATEFUL, *OPENSSL, *FALCON, *PROJECT]
    if args.backends == "r2_probe":
        selected = ["r2_probe"]
        raw_path = args.output / "raw_samples.csv"
        if raw_path.exists() or (args.output / "progress.json").exists():
            raise FileExistsError("Calibration output already contains progress or raw samples.")
        _write_progress(args.output, selected, [], started_at)
        _r2_probe(args.output, args.session_index, args.samples, 20 if args.quick else 10_000)
        rows = _read_raw_rows(raw_path)
        _write_csv(args.output / "calibration_summary.csv", _summary(rows))
        ended_at = datetime.now(UTC).isoformat()
        (args.output / "environment.json").write_text(
            json.dumps(_environment(started_at, ended_at), indent=2) + "\n", encoding="utf-8"
        )
        protocol = {
            "schema_version": "revision-r2-probe-v1",
            "evidence_label": "REAL-CRYPTO",
            "backend": "ed25519_cryptography",
            "invalid_verify_per_variant": args.samples,
            "invalid_variants": ["single_bit_flip", "random_bytes"],
            "overhead_samples_per_operation": 20 if args.quick else 10_000,
            "timer": "time.perf_counter_ns",
            "quick_mode": args.quick,
        }
        (args.output / "calibration_protocol.json").write_text(
            json.dumps(protocol, indent=2) + "\n", encoding="utf-8"
        )
        _write_progress(args.output, selected, ["r2_probe"], started_at, status="complete")
        _sha_manifest(args.output)
        return
    selected = all_labels if args.backends == "all" else [item.strip() for item in args.backends.split(",") if item.strip()]
    unknown = sorted(set(selected) - set(all_labels))
    if unknown or not selected:
        raise ValueError(f"Unknown or empty backend selection: {unknown}")
    raw_path = args.output / "raw_samples.csv"
    if raw_path.exists() or (args.output / "progress.json").exists():
        raise FileExistsError("Calibration output already contains progress or raw samples.")
    completed = []
    _write_progress(args.output, selected, completed, started_at)
    for session in range(args.session_index, args.session_index + args.sessions):
        for label in selected:
            backend_rows = []
            if label in ED25519:
                _calibrate_simple(label, _Ed25519, session, (args.keygen, args.samples), backend_rows)
            elif label in STATEFUL:
                _calibrate_stateful(label, STATEFUL[label], session, (args.keygen, args.samples), backend_rows)
            elif label in OPENSSL:
                _calibrate_openssl(label, OPENSSL[label], session, (args.keygen, args.samples), backend_rows)
            elif label in FALCON:
                _calibrate_falcon(label, FALCON[label], session, (args.keygen, args.samples), backend_rows)
            else:
                backend_class, mode = PROJECT[label]
                _calibrate_project(label, backend_class, mode, session, (args.keygen, args.samples), backend_rows, 0x5A17)
            _append_raw_rows(raw_path, backend_rows)
            completed_id = f"session-{session}:{label}"
            completed.append(completed_id)
            _write_progress(args.output, selected, completed, started_at)
    persistence_labels = [label for label in selected if label in STATEFUL or label in PROJECT]
    if persistence_labels:
        persistence_rows = []
        _durable_persistence(args.output, persistence_rows, args.persistence_samples, persistence_labels)
        _append_raw_rows(raw_path, persistence_rows)
    rows = _read_raw_rows(raw_path)
    summary = _summary(rows)
    _write_csv(args.output / "calibration_summary.csv", summary)
    parity = _timed_region_parity(selected, args.session_index, args.quick)
    _write_csv(args.output / "timed_region_parity.csv", parity)
    ended_at = datetime.now(UTC).isoformat()
    (args.output / "environment.json").write_text(json.dumps(_environment(started_at, ended_at), indent=2) + "\n", encoding="utf-8")
    protocol = {"schema_version": "step-d-portable-v1", "evidence_label": "REAL-CRYPTO",
                "sessions_in_this_artifact": args.sessions, "session_index": args.session_index,
                "keygen_per_backend_per_session": args.keygen, "sign_per_backend_per_session": args.samples,
                "verify_per_backend_per_session": args.samples, "warmup": "one untimed key generation before sign/verify loops",
                "message_size_bytes": 32, "seed_policy": "SHA-256-derived messages; deterministic lifetime seed 23063",
                "lifetime_sampling": "uniform without replacement over leaf indices 0..1023",
                "accepted_sampling": "deterministic sampling over leaf indices 20..69",
                "elapsed_seconds": time.perf_counter() - started_clock, "quick_mode": args.quick}
    (args.output / "calibration_protocol.json").write_text(json.dumps(protocol, indent=2) + "\n", encoding="utf-8")
    _write_progress(args.output, selected, completed, started_at, status="complete")
    _sha_manifest(args.output)


def _campaign_elapsed_seconds(output: Path) -> float:
    starts = {}
    elapsed = 0.0
    log_path = output / "calibration_run.log"
    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) != 5 or parts[0] not in {"START", "DONE"} or parts[2] != "session":
                continue
            key = (parts[1], parts[3])
            try:
                timestamp = datetime.fromisoformat(parts[4])
            except ValueError:
                continue
            if parts[0] == "START":
                starts[key] = timestamp
            elif key in starts:
                elapsed += (timestamp - starts.pop(key)).total_seconds()
    if elapsed <= 0:
        raise RuntimeError("Calibration campaign timestamps are incomplete.")
    return elapsed


def _write_manifest(args, comparisons, elapsed_seconds):
    manifest = {
        "schema_version": "revision-r1-real-crypto-calibration-v1", "evidence_label": "REAL-CRYPTO",
        "created_at_utc": datetime.now(UTC).isoformat(), "elapsed_seconds": elapsed_seconds,
        "sessions": args.sessions, "keygen_per_session": args.keygen, "sign_per_session": args.samples,
        "verify_per_session": args.samples, "invalid_verify_per_variant_per_session": args.samples,
        "message_size_bytes": 32, "deterministic_lifetime_seed": 0x5A17,
        "backends": {"stateful_liboqs": STATEFUL, "openssl": OPENSSL, "falcon_liboqs": FALCON, "project_local_lifetime": list(PROJECT)},
        "environment": _environment(), "lifetime_comparison": comparisons,
        "limitations": [
            "Sequential sessions on one host are not independent hardware replications.",
            "OpenSSL default-provider implementations are not evidence of FIPS-validated module certification.",
            "Persistence timing measures atomic write, file fsync, replace, and directory fsync on the project filesystem.",
            "The Welch p value uses a normal approximation; effect size and raw distributions are primary.",
        ],
    }
    (args.output / "calibration_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
