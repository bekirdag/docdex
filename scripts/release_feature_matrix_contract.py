#!/usr/bin/env python3
"""Strict contracts for release feature-matrix external adapters."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import time
from typing import Mapping, Sequence


EXTERNAL_REQUIRED_CHECKS: dict[str, tuple[str, ...]] = {
    "external_user_memory": (
        "authenticated_push",
        "authenticated_feed",
        "encrypted_roundtrip",
        "principal_scope_isolation",
    ),
    "external_admin": (
        "service_token_required",
        "repo_lifecycle",
        "access_binding_enforced",
    ),
    "external_introspection": (
        "active_token_accepted",
        "inactive_token_rejected",
        "scope_enforced",
    ),
    "external_web": (
        "web_enabled",
        "uncached_provider_response",
        "source_provenance",
    ),
    "external_delegation": (
        "healthy_agent_discovered",
        "real_completion",
        "usage_telemetry",
    ),
}

FIXED_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
}

CONTEXT_ENV_NAMES = {
    "HOME",
    "DOCDEX_STATE_DIR",
    "DOCDEX_GLOBAL_STATE_DIR",
    "DOCDEX_DAEMON_LOCK_PATH",
    "DOCDEX_HTTP_BASE_URL",
    "DOCDEX_FEATURE_MATRIX_REPO_ROOT",
    "DOCDEX_FEATURE_MATRIX_REPO_ID",
    "DOCDEX_FEATURE_MATRIX_LANE",
    "DOCDEX_FEATURE_MATRIX_LANE_MODE",
    "DOCDEX_FEATURE_MATRIX_LANE_EVIDENCE",
    "DOCDEX_FEATURE_MATRIX_SCRIPT_SHA256",
    "DOCDEX_BIN",
}

UNSAFE_ENV_NAMES = {
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "CDPATH",
    "GLOBIGNORE",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PYTHONHOME",
    "PYTHONPATH",
    "RUBYOPT",
    "NODE_OPTIONS",
    "IFS",
    "PS4",
    "PROMPT_COMMAND",
    "PERL5OPT",
    "PERL5LIB",
    "RUSTC_WRAPPER",
    "RUSTFLAGS",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
}

ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class ContractError(ValueError):
    """Raised when release evidence or adapter configuration is unsafe."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_in_repo_script(script_path: Path, repo_root: Path) -> tuple[Path, str]:
    root = repo_root.resolve(strict=True)
    script = script_path.resolve(strict=True)
    try:
        relative = script.relative_to(root)
    except ValueError as exc:
        raise ContractError(
            f"external adapter must resolve inside the repository: {script}"
        ) from exc
    if not script.is_file():
        raise ContractError(f"external adapter is not a regular file: {script}")
    if not os.access(script, os.X_OK):
        raise ContractError(f"external adapter is not executable: {script}")
    return script, relative.as_posix()


def parse_env_allowlist(raw: str) -> tuple[str, ...]:
    names: list[str] = []
    for value in re.split(r"[,\s]+", raw.strip()):
        if not value:
            continue
        if not ENV_NAME_RE.fullmatch(value):
            raise ContractError(f"invalid environment allowlist name: {value!r}")
        if (
            value in CONTEXT_ENV_NAMES
            or value in FIXED_ENVIRONMENT
            or value.startswith("DOCDEX_FEATURE_MATRIX_")
        ):
            raise ContractError(f"environment allowlist cannot override harness context: {value}")
        if (
            value in UNSAFE_ENV_NAMES
            or value.startswith("DYLD_")
            or value.startswith("GIT_CONFIG_KEY_")
            or value.startswith("GIT_CONFIG_VALUE_")
        ):
            raise ContractError(f"unsafe environment variable cannot be forwarded: {value}")
        if value not in names:
            names.append(value)
    return tuple(names)


def build_adapter_environment(
    source: Mapping[str, str],
    explicit_allowlist: Sequence[str],
    context: Mapping[str, str],
) -> dict[str, str]:
    unknown_context = set(context) - CONTEXT_ENV_NAMES
    if unknown_context:
        raise ContractError(
            "unexpected adapter context variables: " + ", ".join(sorted(unknown_context))
        )

    environment = dict(FIXED_ENVIRONMENT)

    for name in explicit_allowlist:
        if (
            name in CONTEXT_ENV_NAMES
            or name in FIXED_ENVIRONMENT
            or name in UNSAFE_ENV_NAMES
        ):
            raise ContractError(f"unsafe or reserved environment allowlist name: {name}")
        value = source.get(name)
        if value is None or not value.strip():
            raise ContractError(f"allowlisted environment prerequisite is missing: {name}")
        environment[name] = value

    for name, value in context.items():
        if not isinstance(value, str) or not value:
            raise ContractError(f"adapter context value is empty: {name}")
        environment[name] = value
    return environment


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "posix":
        os.killpg(process.pid, signal.SIGTERM)
    else:
        process.terminate()
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    if os.name == "posix":
        os.killpg(process.pid, signal.SIGKILL)
    else:
        process.kill()
    process.wait(timeout=2)


def run_external_adapter(
    *,
    script_path: Path,
    repo_root: Path,
    log_path: Path,
    timeout_seconds: int,
    source_environment: Mapping[str, str],
    explicit_allowlist: Sequence[str],
    context: Mapping[str, str],
) -> dict[str, object]:
    if timeout_seconds < 1 or timeout_seconds > 900:
        raise ContractError("external adapter timeout must be between 1 and 900 seconds")
    script, relative_script = canonical_in_repo_script(script_path, repo_root)
    digest_before = sha256_file(script)
    if not SHA256_RE.fullmatch(digest_before):
        raise ContractError("unable to compute external adapter SHA-256")

    adapter_context = dict(context)
    adapter_context["DOCDEX_FEATURE_MATRIX_SCRIPT_SHA256"] = digest_before
    environment = build_adapter_environment(
        source_environment,
        explicit_allowlist,
        adapter_context,
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    started_ns = time.monotonic_ns()
    timed_out = False
    return_code: int | None = None
    runner_error: str | None = None
    process = subprocess.Popen(
        [str(script)],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=os.name == "posix",
    )
    try:
        return_code = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process(process)
        return_code = 124
    except BaseException:
        _terminate_process(process)
        raise
    duration_ms = max(1, round((time.monotonic_ns() - started_ns) / 1_000_000))

    digest_after = sha256_file(script)
    if digest_after != digest_before:
        runner_error = "external adapter changed while it was executing"

    safe_log = {
        "schema_version": 1,
        "adapter_output": "suppressed",
        "return_code": return_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "script_path": relative_script,
        "script_sha256": digest_before,
        "environment_names": sorted(environment),
        "runner_error": runner_error,
    }
    tmp_log = log_path.with_name(log_path.name + ".tmp")
    tmp_log.write_text(
        json.dumps(safe_log, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp_log, log_path)

    return {
        "return_code": return_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "script_path": relative_script,
        "script_sha256": digest_before,
        "environment_names": sorted(environment),
        "runner_error": runner_error,
    }


def _require_nonempty_text(value: object, label: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{label} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise ContractError(f"{label} exceeds {maximum} characters")
    return normalized


def validate_external_evidence(
    *,
    evidence_path: Path,
    copy_path: Path,
    expected_lane: str,
    expected_base_url: str,
    expected_repo_id: str,
    expected_mode: str,
    expected_script_path: str,
    expected_script_sha256: str,
    environment_names: Sequence[str],
) -> dict[str, object]:
    required_checks = EXTERNAL_REQUIRED_CHECKS.get(expected_lane)
    if required_checks is None:
        raise ContractError(f"unknown external lane: {expected_lane}")
    if expected_mode not in {"real", "mock"}:
        raise ContractError("external adapter mode must be explicitly real or mock")
    if not SHA256_RE.fullmatch(expected_script_sha256):
        raise ContractError("expected external adapter SHA-256 is invalid")
    provenance_path = PurePosixPath(expected_script_path)
    if (
        not expected_script_path
        or provenance_path.is_absolute()
        or ".." in provenance_path.parts
    ):
        raise ContractError("expected external adapter provenance path is invalid")
    if not all(isinstance(name, str) and ENV_NAME_RE.fullmatch(name) for name in environment_names):
        raise ContractError("external adapter environment names are invalid")
    if not evidence_path.is_file():
        raise ContractError("missing DOCDEX_FEATURE_MATRIX_LANE_EVIDENCE JSON")

    try:
        data = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"unable to read external lane evidence: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractError("lane evidence must be a JSON object")

    expected_keys = {
        "schema_version",
        "lane",
        "base_url",
        "repo_id",
        "mode",
        "script_sha256",
        "adapter",
        "checks",
    }
    missing_keys = sorted(expected_keys - set(data))
    unknown_keys = sorted(set(data) - expected_keys)
    if missing_keys:
        raise ContractError("lane evidence missing fields: " + ", ".join(missing_keys))
    if unknown_keys:
        raise ContractError("lane evidence contains unsupported fields: " + ", ".join(unknown_keys))
    if data.get("schema_version") != 1:
        raise ContractError("lane evidence schema_version must be 1")

    expected_values = {
        "lane": expected_lane,
        "base_url": expected_base_url,
        "repo_id": expected_repo_id,
        "mode": expected_mode,
        "script_sha256": expected_script_sha256,
    }
    for key, expected in expected_values.items():
        if data.get(key) != expected:
            raise ContractError(f"lane evidence {key} mismatch")

    adapter = data.get("adapter")
    if not isinstance(adapter, dict) or set(adapter) != {"name", "version", "provider"}:
        raise ContractError(
            "lane evidence adapter must contain exactly name, version, and provider"
        )
    normalized_adapter = {
        key: _require_nonempty_text(adapter.get(key), f"adapter.{key}", 120)
        for key in ("name", "version", "provider")
    }

    checks = data.get("checks")
    if not isinstance(checks, list) or not checks:
        raise ContractError("lane evidence checks must be a non-empty array")
    normalized_checks: list[dict[str, object]] = []
    names: list[str] = []
    for index, check in enumerate(checks):
        if not isinstance(check, dict) or set(check) != {"name", "passed", "evidence"}:
            raise ContractError(
                f"check {index} must contain exactly name, passed, and evidence"
            )
        name = _require_nonempty_text(check.get("name"), f"check {index} name", 120)
        if check.get("passed") is not True:
            raise ContractError(f"check {name!r} did not pass")
        evidence = _require_nonempty_text(
            check.get("evidence"), f"check {name!r} evidence", 700
        )
        evidence_sha256 = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
        names.append(name)
        normalized_checks.append(
            {"name": name, "passed": True, "evidence_sha256": evidence_sha256}
        )
    if len(names) != len(set(names)):
        raise ContractError("lane evidence check names must be unique")
    if set(names) != set(required_checks) or len(names) != len(required_checks):
        missing = sorted(set(required_checks) - set(names))
        unexpected = sorted(set(names) - set(required_checks))
        detail: list[str] = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if unexpected:
            detail.append("unexpected=" + ",".join(unexpected))
        raise ContractError(
            f"lane {expected_lane} evidence checks do not match the required contract"
            + (": " + " ".join(detail) if detail else "")
        )

    normalized_data = {
        **expected_values,
        "schema_version": 1,
        "adapter": normalized_adapter,
        "checks": normalized_checks,
    }
    copy_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_copy = copy_path.with_name(copy_path.name + ".tmp")
    tmp_copy.write_text(
        json.dumps(normalized_data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(tmp_copy, copy_path)
    evidence_sha256 = sha256_file(copy_path)
    return {
        "adapter": normalized_adapter,
        "checks": list(required_checks),
        "script_path": expected_script_path,
        "script_sha256": expected_script_sha256,
        "evidence_sha256": evidence_sha256,
        "environment_names": sorted(set(environment_names)),
    }


def _run_adapter_command(args: argparse.Namespace) -> int:
    context = {
        "HOME": args.home,
        "DOCDEX_STATE_DIR": args.state,
        "DOCDEX_GLOBAL_STATE_DIR": args.global_state,
        "DOCDEX_DAEMON_LOCK_PATH": str(Path(args.state) / "daemon.lock"),
        "DOCDEX_HTTP_BASE_URL": args.base_url,
        "DOCDEX_FEATURE_MATRIX_REPO_ROOT": args.repo_path,
        "DOCDEX_FEATURE_MATRIX_REPO_ID": args.repo_id,
        "DOCDEX_FEATURE_MATRIX_LANE": args.lane,
        "DOCDEX_FEATURE_MATRIX_LANE_MODE": args.mode,
        "DOCDEX_FEATURE_MATRIX_LANE_EVIDENCE": args.evidence,
        "DOCDEX_BIN": args.docdex_bin,
    }
    try:
        result = run_external_adapter(
            script_path=Path(args.script),
            repo_root=Path(args.root_dir),
            log_path=Path(args.log),
            timeout_seconds=args.timeout,
            source_environment=os.environ,
            explicit_allowlist=parse_env_allowlist(args.env_allowlist),
            context=context,
        )
    except (ContractError, OSError, subprocess.SubprocessError) as exc:
        result = {
            "return_code": None,
            "timed_out": False,
            "duration_ms": 1,
            "script_path": "",
            "script_sha256": "",
            "environment_names": [],
            "runner_error": str(exc),
        }
    print(json.dumps(result, sort_keys=True))
    return 0


def _validate_evidence_command(args: argparse.Namespace) -> int:
    try:
        environment_names = json.loads(args.environment_names_json)
        if not isinstance(environment_names, list):
            raise ContractError("environment-names-json must contain an array")
        provenance = validate_external_evidence(
            evidence_path=Path(args.evidence),
            copy_path=Path(args.copy),
            expected_lane=args.lane,
            expected_base_url=args.base_url,
            expected_repo_id=args.repo_id,
            expected_mode=args.mode,
            expected_script_path=args.script_path,
            expected_script_sha256=args.script_sha256,
            environment_names=environment_names,
        )
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(provenance, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    describe = subparsers.add_parser("describe", help="Print external evidence contracts")
    describe.set_defaults(
        handler=lambda _args: (
            print(json.dumps(EXTERNAL_REQUIRED_CHECKS, indent=2, sort_keys=True)) or 0
        )
    )

    run = subparsers.add_parser("run-adapter", help="Run one external adapter safely")
    for name in (
        "script",
        "root-dir",
        "log",
        "home",
        "state",
        "global-state",
        "evidence",
        "lane",
        "base-url",
        "repo-path",
        "repo-id",
        "mode",
        "docdex-bin",
    ):
        run.add_argument(f"--{name}", required=True)
    run.add_argument("--timeout", required=True, type=int)
    run.add_argument("--env-allowlist", default="")
    run.set_defaults(handler=_run_adapter_command)

    validate = subparsers.add_parser(
        "validate-evidence", help="Validate and copy one external evidence document"
    )
    for name in (
        "evidence",
        "copy",
        "lane",
        "base-url",
        "repo-id",
        "mode",
        "script-path",
        "script-sha256",
        "environment-names-json",
    ):
        validate.add_argument(f"--{name}", required=True)
    validate.set_defaults(handler=_validate_evidence_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
