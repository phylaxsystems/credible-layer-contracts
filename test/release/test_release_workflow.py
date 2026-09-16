import json
import re
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTest(unittest.TestCase):
    def test_artifacts_are_verified_before_upload(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        artifact_job = workflow.split("  create-artifacts:\n", 1)[1].split(
            "  release-npm-verify:\n", 1
        )[0]

        generation_index = artifact_job.index("run: ./shell/create_artifacts.sh")
        verification_index = artifact_job.index(
            "run: git diff --exit-code -- bindings/rust/abi/IStateOracleV1.json bindings/rust/abi/IStateOracleV2.json"
        )
        upload_index = artifact_job.index("uses: actions/upload-artifact@")

        self.assertLess(generation_index, verification_index)
        self.assertLess(verification_index, upload_index)

    def test_artifact_generation_inputs_are_immutable(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        artifact_job = workflow.split("  create-artifacts:\n", 1)[1].split(
            "  release-npm-verify:\n", 1
        )[0]
        action_references = [
            line.strip()
            for line in artifact_job.splitlines()
            if line.strip().startswith("uses:")
        ]

        self.assertTrue(action_references)
        for action_reference in action_references:
            self.assertIsNotNone(
                re.fullmatch(
                    r"uses: [^@\s]+@[0-9a-f]{40}(?:\s+#\s+\S+)?",
                    action_reference,
                ),
                action_reference,
            )
        self.assertRegex(artifact_job, r"version: v\d+\.\d+\.\d+")
        self.assertNotIn("version: nightly", artifact_job)
        self.assertNotIn("version: stable", artifact_job)

    def test_npm_package_verification_has_no_oidc_permission(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        verify_job = workflow.split("  release-npm-verify:\n", 1)[1].split(
            "  release-npm:\n", 1
        )[0]

        self.assertIn("needs: create-artifacts", verify_job)
        self.assertIn("contents: read", verify_job)
        self.assertNotIn("id-token: write", verify_job)
        self.assertIn("uses: actions/checkout@", verify_job)
        self.assertIn("uses: actions/setup-node@", verify_job)
        self.assertIn("uses: actions/download-artifact@", verify_job)
        self.assertIn("name: credible-layer-contracts-artifacts", verify_job)
        self.assertIn("npm pack --ignore-scripts=true --json", verify_job)
        self.assertIn("uses: actions/upload-artifact@", verify_job)
        self.assertIn("name: credible-layer-contracts-npm-package", verify_job)

    def test_npm_publish_job_only_publishes_verified_package(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        release_job = workflow.split("  release-npm:\n", 1)[1].split(
            "  release-github:\n", 1
        )[0]

        self.assertIn("needs: release-npm-verify", release_job)
        self.assertIn("id-token: write", release_job)
        self.assertNotIn("actions/checkout", release_job)
        self.assertIn("uses: actions/setup-node@", release_job)
        self.assertIn("node-version: 24.18.1", release_job)
        self.assertIn("registry-url: https://registry.npmjs.org", release_job)
        self.assertIn("uses: actions/download-artifact@", release_job)
        self.assertIn("name: credible-layer-contracts-npm-package", release_job)
        self.assertIn(
            'npm publish "${packages[0]}" --access public --ignore-scripts=true',
            release_job,
        )
        self.assertNotIn("npm install", release_job)
        self.assertNotIn("npm pack --", release_job)

    def test_npm_release_actions_are_pinned_to_commit_shas(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        npm_jobs = workflow.split("  release-npm-verify:\n", 1)[1].split(
            "  release-github:\n", 1
        )[0]
        action_references = [
            line.strip()
            for line in npm_jobs.splitlines()
            if line.strip().startswith("uses:")
        ]

        self.assertTrue(action_references)
        for action_reference in action_references:
            self.assertIsNotNone(
                re.fullmatch(
                    r"uses: [^@\s]+@[0-9a-f]{40}(?:\s+#\s+\S+)?",
                    action_reference,
                ),
                action_reference,
            )

    def test_rust_bindings_have_no_registry_publication_path(self):
        release_workflow = (
            ROOT / ".github" / "workflows" / "release.yml"
        ).read_text()
        ci_workflow = (
            ROOT / ".github" / "workflows" / "solidity-test.yml"
        ).read_text()
        publication_markers = (
            "cargo publish",
            "crates.io",
            "crates-io-auth-action",
            "CARGO_REGISTRY_TOKEN",
            "release-cargo",
        )

        for marker in publication_markers:
            self.assertNotIn(marker, release_workflow)
            self.assertNotIn(marker, ci_workflow)

    def test_github_release_is_local_and_uses_pinned_artifacts(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        release_job = workflow.split("  release-github:\n", 1)[1]
        action_references = [
            line.strip()
            for line in release_job.splitlines()
            if line.strip().startswith("uses:")
        ]

        self.assertIn("runs-on: ubuntu-latest", release_job)
        self.assertIn("contents: write", release_job)
        self.assertNotIn("id-token: write", release_job)
        self.assertNotIn("phylaxsystems/actions", release_job)
        self.assertNotIn("SSH_PRIVATE_KEY", release_job)
        self.assertNotIn("actions/checkout", release_job)
        self.assertIn("uses: actions/download-artifact@", release_job)
        self.assertIn("name: credible-layer-contracts-artifacts", release_job)
        self.assertIn("gh release create", release_job)
        self.assertIn('"$GITHUB_REF_NAME"', release_job)
        self.assertIn("--generate-notes", release_job)

        self.assertTrue(action_references)
        for action_reference in action_references:
            self.assertIsNotNone(
                re.fullmatch(
                    r"uses: [^@\s]+@[0-9a-f]{40}(?:\s+#\s+\S+)?",
                    action_reference,
                ),
                action_reference,
            )

    def test_rust_bindings_are_not_publishable(self):
        package = json.loads((ROOT / "package.json").read_text())
        with (ROOT / "bindings" / "rust" / "Cargo.toml").open("rb") as manifest:
            cargo_package = tomllib.load(manifest)["package"]

        self.assertEqual(cargo_package["name"], "credible-layer-contracts")
        self.assertEqual(cargo_package["version"], package["version"])
        self.assertIs(cargo_package["publish"], False)
        self.assertEqual(cargo_package["license"], "MIT OR Apache-2.0")

    def test_ci_enforces_cargo_msrv(self):
        workflow = (ROOT / ".github" / "workflows" / "solidity-test.yml").read_text()
        msrv_job = workflow.split("  rust-bindings-msrv:\n", 1)[1].split(
            "  solidity-base:\n", 1
        )[0]
        with (ROOT / "bindings" / "rust" / "Cargo.toml").open("rb") as manifest:
            rust_version = tomllib.load(manifest)["package"]["rust-version"]
        rust_toolchain = (
            f"{rust_version}.0" if rust_version.count(".") == 1 else rust_version
        )

        self.assertIn(f"rustup toolchain install {rust_toolchain}", msrv_job)
        self.assertIn(
            f"cargo +{rust_toolchain} test --manifest-path bindings/rust/Cargo.toml",
            msrv_job,
        )

    def test_artifact_generation_updates_the_committed_rust_abi(self):
        script = (ROOT / "shell" / "create_artifacts.sh").read_text()

        self.assertIn('bindings/rust/abi', script)
        self.assertIn('cp "${INTERFACES}/IStateOracleV1.json"', script)
        self.assertIn('cp "${INTERFACES}/IStateOracleV2.json"', script)

    def test_state_oracle_release_mapping_preserves_supported_abis(self):
        readme = (ROOT / "bindings" / "rust" / "README.md").read_text()
        rust_source = (ROOT / "bindings" / "rust" / "src" / "lib.rs").read_text()

        self.assertIn(
            "| `0.2.0` | `IStateOracleV1` | `state_oracle::v1` |", readme
        )
        self.assertIn(
            "| `0.3.0` | `IStateOracleV2` | `state_oracle::v2` |", readme
        )
        self.assertIn("pub mod v1", rust_source)
        self.assertIn("pub mod v2", rust_source)

    def test_gas_snapshot_uses_a_pinned_foundry_version(self):
        workflow = (ROOT / ".github" / "workflows" / "solidity-test.yml").read_text()
        solidity_job = workflow.split("  solidity-base:\n", 1)[1].split(
            "  gas-snapshot:\n", 1
        )[0]
        gas_job = workflow.split("  gas-snapshot:\n", 1)[1].split(
            "  contract-compatibility:\n", 1
        )[0]

        self.assertIn("disable-gas-snapshot: true", solidity_job)
        self.assertRegex(gas_job, r"version: v\d+\.\d+\.\d+")
        self.assertNotIn("version: nightly", gas_job)
        self.assertNotIn("version: stable", gas_job)
        self.assertIn("forge snapshot --check --silent --tolerance 25", gas_job)

    def test_solidity_compiler_version_is_pinned(self):
        foundry_config = (ROOT / "foundry.toml").read_text()

        self.assertRegex(foundry_config, r'(?m)^solc = "\d+\.\d+\.\d+"$')

    def test_package_requests_provenance(self):
        package = json.loads((ROOT / "package.json").read_text())

        self.assertEqual(package["publishConfig"]["access"], "public")
        self.assertIs(package["publishConfig"]["provenance"], True)


if __name__ == "__main__":
    unittest.main()
