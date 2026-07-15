#!/usr/bin/env python3
"""Focused regressions for the release feature-matrix harness contract."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True
SCRIPT_DIR = Path(__file__).resolve().parent
CONTRACT_PATH = SCRIPT_DIR / "release_feature_matrix_contract.py"
SPEC = importlib.util.spec_from_file_location("release_feature_matrix_contract", CONTRACT_PATH)
assert SPEC and SPEC.loader
contract = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(contract)


class ReleaseFeatureMatrixContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def evidence_for(self, lane: str, digest: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "lane": lane,
            "base_url": "http://127.0.0.1:49152",
            "repo_id": "repo-contract-test",
            "mode": "real",
            "script_sha256": digest,
            "adapter": {
                "name": f"{lane}-adapter",
                "version": "1.0.0",
                "provider": "contract-test",
            },
            "checks": [
                {"name": name, "passed": True, "evidence": f"verified {name}"}
                for name in contract.EXTERNAL_REQUIRED_CHECKS[lane]
            ],
        }

    def validate(self, lane: str, data: dict[str, object]) -> dict[str, object]:
        evidence = self.root / f"{lane}.json"
        copied = self.root / f"{lane}.copied.json"
        evidence.write_text(json.dumps(data), encoding="utf-8")
        return contract.validate_external_evidence(
            evidence_path=evidence,
            copy_path=copied,
            expected_lane=lane,
            expected_base_url="http://127.0.0.1:49152",
            expected_repo_id="repo-contract-test",
            expected_mode="real",
            expected_script_path=f"scripts/adapters/{lane}.sh",
            expected_script_sha256=data["script_sha256"],
            environment_names=("HOME", "PATH"),
        )

    def test_every_external_lane_requires_its_exact_check_contract(self) -> None:
        digest = "a" * 64
        for lane, required_checks in contract.EXTERNAL_REQUIRED_CHECKS.items():
            with self.subTest(lane=lane):
                provenance = self.validate(lane, self.evidence_for(lane, digest))
                self.assertEqual(provenance["checks"], list(required_checks))
                self.assertEqual(provenance["script_sha256"], digest)
                self.assertRegex(provenance["evidence_sha256"], r"^[0-9a-f]{64}$")

    def test_arbitrary_or_missing_evidence_checks_are_rejected(self) -> None:
        lane = "external_web"
        digest = "b" * 64
        arbitrary = self.evidence_for(lane, digest)
        arbitrary["checks"].append(
            {"name": "arbitrary_success", "passed": True, "evidence": "not a contract"}
        )
        with self.assertRaisesRegex(contract.ContractError, "unexpected=arbitrary_success"):
            self.validate(lane, arbitrary)

        missing = self.evidence_for(lane, digest)
        missing["checks"] = missing["checks"][1:]
        with self.assertRaisesRegex(contract.ContractError, "missing=web_enabled"):
            self.validate(lane, missing)

    def test_evidence_requires_explicit_mode_digest_and_strict_schema(self) -> None:
        lane = "external_admin"
        digest = "c" * 64
        data = self.evidence_for(lane, digest)
        data["mode"] = ""
        with self.assertRaisesRegex(contract.ContractError, "mode mismatch"):
            self.validate(lane, data)

        data = self.evidence_for(lane, digest)
        data["script_sha256"] = "d" * 64
        with self.assertRaisesRegex(contract.ContractError, "script_sha256 mismatch"):
            contract.validate_external_evidence(
                evidence_path=self._write_json("digest.json", data),
                copy_path=self.root / "digest.copy.json",
                expected_lane=lane,
                expected_base_url="http://127.0.0.1:49152",
                expected_repo_id="repo-contract-test",
                expected_mode="real",
                expected_script_path="scripts/adapters/admin.sh",
                expected_script_sha256=digest,
                environment_names=(),
            )

        data = self.evidence_for(lane, digest)
        data["arbitrary"] = True
        with self.assertRaisesRegex(contract.ContractError, "unsupported fields"):
            self.validate(lane, data)

    def _write_json(self, name: str, data: object) -> Path:
        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_adapter_runner_forwards_only_allowlisted_environment_and_records_provenance(
        self,
    ) -> None:
        script = self.root / "adapter.py"
        evidence = self.root / "adapter-env.json"
        script.write_text(
            """#!/usr/bin/env python3
import json
import os
import time
time.sleep(0.02)
print("adapter token=" + os.environ.get("ALLOWED_TOKEN", ""))
print("adapter stderr secret", file=__import__("sys").stderr)
with open(os.environ["DOCDEX_FEATURE_MATRIX_LANE_EVIDENCE"], "w", encoding="utf-8") as handle:
    json.dump({
        "allowed": os.environ.get("ALLOWED_TOKEN"),
        "forbidden": os.environ.get("FORBIDDEN_SECRET"),
        "script_sha256": os.environ.get("DOCDEX_FEATURE_MATRIX_SCRIPT_SHA256"),
    }, handle)
""",
            encoding="utf-8",
        )
        script.chmod(0o755)
        context = {
            "HOME": str(self.root / "home"),
            "DOCDEX_STATE_DIR": str(self.root / "state"),
            "DOCDEX_GLOBAL_STATE_DIR": str(self.root / "global"),
            "DOCDEX_DAEMON_LOCK_PATH": str(self.root / "state" / "daemon.lock"),
            "DOCDEX_HTTP_BASE_URL": "http://127.0.0.1:49152",
            "DOCDEX_FEATURE_MATRIX_REPO_ROOT": str(self.root),
            "DOCDEX_FEATURE_MATRIX_REPO_ID": "repo-contract-test",
            "DOCDEX_FEATURE_MATRIX_LANE": "external_web",
            "DOCDEX_FEATURE_MATRIX_LANE_MODE": "real",
            "DOCDEX_FEATURE_MATRIX_LANE_EVIDENCE": str(evidence),
            "DOCDEX_BIN": "/tmp/docdexd",
        }
        source_environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "ALLOWED_TOKEN": "allowed-value",
            "FORBIDDEN_SECRET": "must-not-leak",
        }
        adapter_log = self.root / "adapter.log"
        result = contract.run_external_adapter(
            script_path=script,
            repo_root=self.root,
            log_path=adapter_log,
            timeout_seconds=5,
            source_environment=source_environment,
            explicit_allowlist=("ALLOWED_TOKEN",),
            context=context,
        )
        observed = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(result["return_code"], 0)
        self.assertFalse(result["timed_out"])
        self.assertGreaterEqual(result["duration_ms"], 10)
        self.assertEqual(result["script_path"], "adapter.py")
        self.assertRegex(result["script_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(observed["allowed"], "allowed-value")
        self.assertIsNone(observed["forbidden"])
        self.assertEqual(observed["script_sha256"], result["script_sha256"])
        self.assertNotIn("FORBIDDEN_SECRET", result["environment_names"])
        safe_log = adapter_log.read_text(encoding="utf-8")
        self.assertIn('"adapter_output": "suppressed"', safe_log)
        self.assertNotIn("allowed-value", safe_log)
        self.assertNotIn("adapter stderr secret", safe_log)

    def test_copied_evidence_hashes_arbitrary_text_instead_of_uploading_it(self) -> None:
        lane = "external_web"
        digest = "e" * 64
        data = self.evidence_for(lane, digest)
        secret_text = "credential-like-value-that-must-not-be-uploaded"
        data["checks"][0]["evidence"] = secret_text

        self.validate(lane, data)
        copied = json.loads(
            (self.root / f"{lane}.copied.json").read_text(encoding="utf-8")
        )
        serialized = json.dumps(copied, sort_keys=True)
        self.assertNotIn(secret_text, serialized)
        self.assertRegex(
            copied["checks"][0]["evidence_sha256"], r"^[0-9a-f]{64}$"
        )

    def test_adapter_runner_rejects_out_of_repo_scripts_and_missing_prerequisites(self) -> None:
        outside = Path(tempfile.gettempdir()) / "docdex-feature-matrix-outside.sh"
        outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        outside.chmod(0o755)
        self.addCleanup(outside.unlink, missing_ok=True)
        with self.assertRaisesRegex(contract.ContractError, "inside the repository"):
            contract.canonical_in_repo_script(outside, self.root)
        with self.assertRaisesRegex(contract.ContractError, "prerequisite is missing"):
            contract.build_adapter_environment(
                {"PATH": "/usr/bin:/bin"},
                ("MISSING_TOKEN",),
                {"HOME": str(self.root)},
            )

    def test_unsafe_or_reserved_environment_names_are_rejected(self) -> None:
        for raw in (
            "HOME",
            "PATH",
            "DOCDEX_FEATURE_MATRIX_LANE",
            "LD_PRELOAD",
            "PYTHONPATH",
            "RUSTC_WRAPPER",
            "GIT_CONFIG_KEY_0",
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(contract.ContractError):
                    contract.parse_env_allowlist(raw)

    def test_release_workflows_use_the_optimized_feature_matrix(self) -> None:
        root = SCRIPT_DIR.parent
        for relative in (".github/workflows/release.yml", ".github/workflows/release-dry-run.yml"):
            with self.subTest(workflow=relative):
                text = (root / relative).read_text(encoding="utf-8")
                self.assertIn("cargo build --locked --release --bin docdexd", text)
                self.assertIn(
                    "scripts/test_release_feature_matrix.sh --binary target/release/docdexd",
                    text,
                )
                self.assertNotIn(
                    "scripts/test_release_feature_matrix.sh "
                    "--binary target/release/docdexd --release-gate",
                    text,
                )
                for lane in ("USER_MEMORY", "ADMIN", "INTROSPECTION", "WEB", "DELEGATION"):
                    self.assertIn(f"DOCDEX_FEATURE_MATRIX_{lane}_SCRIPT:", text)
                    self.assertIn(f"DOCDEX_FEATURE_MATRIX_{lane}_MODE: real", text)
                    self.assertIn(f"DOCDEX_FEATURE_MATRIX_{lane}_ENV_ALLOWLIST:", text)

    def test_release_workflow_keeps_postinstall_smoke_outside_oidc_job(self) -> None:
        text = (SCRIPT_DIR.parent / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        prepare_start = text.index("  prepare-npm:\n")
        release_start = text.index("  release-assets:\n")
        publish_start = text.index("  publish-npm:\n")
        mcp_start = text.index("  publish-mcp:\n")
        self.assertLess(prepare_start, release_start)
        self.assertLess(release_start, publish_start)
        self.assertLess(prepare_start, publish_start)
        self.assertLess(publish_start, mcp_start)
        prepare = text[prepare_start:publish_start]
        publish = text[publish_start:mcp_start]

        self.assertIn("needs: prepare-release-assets", prepare)
        self.assertIn("Smoke test install from exact tarball", prepare)
        self.assertIn("npm install \"$PACK_PATH\"", prepare)
        self.assertIn("DOCDEX_DOWNLOAD_BASE=", prepare)
        self.assertIn("immutable-releases", prepare)
        self.assertIn("gh release create", prepare)
        self.assertIn("--draft=false", prepare)
        self.assertNotIn("id-token: write", prepare)

        self.assertIn("- prepare-npm", publish)
        self.assertIn("- release-assets", publish)
        self.assertIn("id-token: write", publish)
        self.assertIn("Download retained npm artifact", publish)
        self.assertIn("Verify exact npm artifact integrity", publish)
        self.assertIn('npm publish "artifacts/npm/${PACK_FILENAME}"', publish)
        self.assertNotIn("Smoke test install", publish)
        self.assertNotIn("uses: actions/checkout@", publish)

    def test_release_publication_stays_bound_to_the_remote_tag_commit(self) -> None:
        text = (SCRIPT_DIR.parent / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        release_start = text.index("  release-assets:\n")
        publish_start = text.index("  publish-npm:\n")
        release = text[release_start:publish_start]

        self.assertIn("verify_remote_tag()", release)
        self.assertIn('git ls-remote --tags origin "refs/tags/${GITHUB_REF_NAME}"', release)
        self.assertIn(
            'git ls-remote --tags origin "refs/tags/${GITHUB_REF_NAME}^{}"',
            release,
        )
        self.assertIn('test "${resolved_sha}" = "${GITHUB_SHA}"', release)
        self.assertIn(
            'test "$(jq -r \'.sourceCommit\' '
            'artifacts/docdex-release-manifest.json)" = "${GITHUB_SHA}"',
            release,
        )
        self.assertIn(
            "verify_remote_tag\n          gh release edit",
            release,
        )
        self.assertIn(
            'test "${IMMUTABLE_RELEASE_VERIFIED}" = "1"\n'
            "          verify_remote_tag",
            release,
        )
        self.assertGreaterEqual(release.count("verify_remote_tag"), 4)

    def test_deploy_workflow_uses_the_verified_release_asset(self) -> None:
        text = (
            SCRIPT_DIR.parent / ".github/workflows/deploy-docdex-server.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("gh release download", text)
        self.assertIn("docdexd-linux-x64-gnu.tar.gz.sha256", text)
        self.assertIn("manifest.sourceCommit", text)
        self.assertIn(".immutable == true", text)
        self.assertIn('test "${GITHUB_REF}" = "refs/heads/main"', text)
        self.assertIn("RELEASE_SHA: ${{ needs.prepare.outputs.release_sha }}", text)
        self.assertNotIn("cargo build", text)
        self.assertNotIn("cargo test", text)
        self.assertNotIn("RELEASE_SHA: ${{ github.sha }}", text)

    def test_release_helper_keeps_deploy_artifacts_out_of_root_execution(self) -> None:
        helper = (SCRIPT_DIR.parent / "server/bin/docdex-apply-release").read_text(
            encoding="utf-8"
        )
        workflow = (
            SCRIPT_DIR.parent / ".github/workflows/deploy-docdex-server.yml"
        ).read_text(encoding="utf-8")
        self.assertIn('STAGING_ROOT="${STAGING_PARENT}/incoming"', helper)
        self.assertIn(
            'EXPECTED_SOURCE="${STAGING_ROOT}/${REVISION}/docdexd"', helper
        )
        self.assertIn('runuser -u "${DEPLOY_USER}" -- /bin/cat', helper)
        self.assertIn('| /bin/cat >"${TEMP_BIN}"', helper)
        self.assertIn('runuser -u "${SERVICE_USER}" -- env -i', helper)
        self.assertNotIn('chown "${DEPLOY_UID}" "${TEMP_BIN}"', helper)
        self.assertIn('/proc/${main_pid}/exe', helper)
        self.assertIn('service_runs_binary "${RELEASE_BIN}"', helper)
        self.assertIn("exit 69", helper)
        self.assertIn("exit 70", helper)
        self.assertIn("systemctl disable docdex.service", helper)
        self.assertIn('RELEASE_BIN="${SOURCE_BIN}"', helper)
        self.assertIn('[[ "${SOURCE_KIND}" == "rollback" ]]', helper)
        self.assertNotIn('if ! "${RELEASE_BIN}" --version', helper)
        self.assertIn("if [[ $# -ne 3 ]]", helper)
        self.assertIn('EXPECTED_SHA256="${3:-}"', helper)
        self.assertIn('[[ ! "${EXPECTED_SHA256}" =~ ^[0-9a-f]{64}$ ]]', helper)
        self.assertIn(
            'if [[ "${TEMP_SHA256}" != "${EXPECTED_SHA256}" ]]; then', helper
        )
        self.assertIn(
            'if [[ "${RELEASE_SHA256}" != "${EXPECTED_SHA256}" ]]; then', helper
        )
        self.assertLess(
            helper.index('TEMP_SHA256="$(sha256sum -- "${TEMP_BIN}"'),
            helper.index('if ! runuser -u "${SERVICE_USER}" -- env -i'),
        )
        self.assertLess(
            helper.index('RELEASE_SHA256="$(sha256sum -- "${RELEASE_BIN}"'),
            helper.index('if ! runuser -u "${SERVICE_USER}" -- env -i'),
        )
        self.assertIn("chmod 0755 dist/docdexd", workflow)
        self.assertIn(
            'RELEASE_DIR="/var/lib/docdex-deploy/incoming/${RELEASE_SHA}"',
            workflow,
        )
        self.assertIn(
            "docdex-apply-release '${RELEASE_DIR}/docdexd' "
            "'${RELEASE_SHA}' '${RELEASE_SHA256}'",
            workflow,
        )
        self.assertIn(
            "docdex-apply-release '${PREVIOUS_BIN}' "
            "'${rollback_revision}' '${PREVIOUS_SHA256}'",
            workflow,
        )

    def test_ci_and_nightly_actions_are_pinned_and_least_privileged(self) -> None:
        root = SCRIPT_DIR.parent
        expected_jobs = {
            ".github/workflows/ci.yml": 3,
            ".github/workflows/nightly.yml": 2,
        }
        for relative, job_count in expected_jobs.items():
            with self.subTest(workflow=relative):
                text = (root / relative).read_text(encoding="utf-8")
                action_lines = [
                    line.strip() for line in text.splitlines() if "uses:" in line
                ]
                self.assertTrue(action_lines)
                for line in action_lines:
                    self.assertRegex(
                        line,
                        r"^uses: [^@\s]+@[0-9a-f]{40}(?:\s+#\s+\S+)?$",
                    )
                self.assertIn("permissions: {}", text)
                self.assertNotIn("write-all", text)
                permission_blocks = re.findall(
                    r"^    permissions:\n((?:      [^\n]+\n)+)",
                    text,
                    flags=re.MULTILINE,
                )
                self.assertEqual(
                    permission_blocks,
                    ["      contents: read\n"] * job_count,
                )
                checkout_count = sum(
                    "uses: actions/checkout@" in line for line in action_lines
                )
                self.assertEqual(text.count("persist-credentials: false"), checkout_count)

    def test_all_workflow_actions_are_commit_pinned(self) -> None:
        workflow_dir = SCRIPT_DIR.parent / ".github/workflows"
        workflows = sorted(
            {*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml")}
        )
        self.assertTrue(workflows)

        def step_tail(lines: list[str], index: int) -> tuple[int, list[str]]:
            uses_indent = len(lines[index]) - len(lines[index].lstrip())
            tail: list[str] = []
            for candidate in lines[index + 1 :]:
                if not candidate.strip() or candidate.lstrip().startswith("#"):
                    continue
                indent = len(candidate) - len(candidate.lstrip())
                if indent < uses_indent:
                    break
                tail.append(candidate)
            return uses_indent, tail

        setup_node_count = 0
        rust_toolchain_count = 0
        for workflow in workflows:
            with self.subTest(workflow=workflow.name):
                text = workflow.read_text(encoding="utf-8")
                lines = text.splitlines()
                action_lines = [line.strip() for line in lines if "uses:" in line]
                for line in action_lines:
                    self.assertRegex(
                        line,
                        r"^uses: [^@\s]+@[0-9a-f]{40}(?:\s+#\s+\S+)?$",
                    )
                for index, line in enumerate(lines):
                    stripped = line.strip()
                    if stripped.startswith("uses: actions/setup-node@"):
                        setup_node_count += 1
                        uses_indent, tail = step_tail(lines, index)
                        self.assertIn(
                            " " * (uses_indent + 2)
                            + "package-manager-cache: false",
                            tail,
                        )
                    if stripped.startswith("uses: dtolnay/rust-toolchain@"):
                        rust_toolchain_count += 1
                        uses_indent, tail = step_tail(lines, index)
                        self.assertIn(
                            " " * (uses_indent + 2) + 'toolchain: "1.97.0"',
                            tail,
                        )
        self.assertGreater(setup_node_count, 0)
        self.assertGreater(rust_toolchain_count, 0)

        toolchain = (SCRIPT_DIR.parent / "rust-toolchain.toml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            re.findall(r'^channel\s*=\s*"([^"]+)"\s*$', toolchain, re.MULTILINE),
            ["1.97.0"],
        )
        self.assertRegex(
            toolchain,
            re.compile(r'^profile\s*=\s*"minimal"\s*$', re.MULTILINE),
        )
        self.assertRegex(
            toolchain,
            re.compile(
                r'^components\s*=\s*\["rustfmt"\]\s*$',
                re.MULTILINE,
            ),
        )

        release_please = (
            SCRIPT_DIR.parent / ".github/workflows/release-please.yml"
        ).read_text(encoding="utf-8")
        permission_declarations = []
        for line in release_please.splitlines():
            match = re.match(r"^(\s*)permissions:\s*(.*?)\s*$", line)
            if match:
                permission_declarations.append((len(match.group(1)), match.group(2)))
        self.assertEqual(permission_declarations, [(0, "{}")])

    def test_harness_keeps_exact_offline_local_inventory(self) -> None:
        text = (SCRIPT_DIR / "test_release_feature_matrix.sh").read_text(
            encoding="utf-8"
        )
        expected_match = re.search(
            r"EXPECTED_LOCAL_LANES=\$'([^']+)'", text
        )
        self.assertIsNotNone(expected_match)
        expected = expected_match.group(1).split(r"\n")
        invoked = re.findall(r'run_lane\("([^"]+)"', text)
        self.assertEqual(len(expected), 24)
        self.assertEqual(len(set(expected)), 24)
        self.assertEqual(invoked, expected)
        self.assertIn("DOCDEX_WEB_ENABLED=0", text)
        self.assertIn("env -i", text)
        self.assertNotIn("env = os.environ.copy()", text)

    def test_run_all_help_and_unknown_arguments_exit_before_the_suite(self) -> None:
        script = SCRIPT_DIR / "test_run_all.sh"
        help_result = subprocess.run(
            ["bash", str(script), "--help"],
            cwd=SCRIPT_DIR.parent,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("Usage: scripts/test_run_all.sh", help_result.stdout)
        self.assertIn("DOCDEX_RUN_EXTENDED_TESTS=1", help_result.stdout)
        self.assertNotIn("start:", help_result.stderr)

        unknown_result = subprocess.run(
            ["bash", str(script), "--definitely-unknown"],
            cwd=SCRIPT_DIR.parent,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertEqual(unknown_result.returncode, 2)
        self.assertIn("unknown argument: --definitely-unknown", unknown_result.stderr)
        self.assertIn("Usage: scripts/test_run_all.sh", unknown_result.stderr)
        self.assertNotIn("start:", unknown_result.stderr)


if __name__ == "__main__":
    unittest.main()
