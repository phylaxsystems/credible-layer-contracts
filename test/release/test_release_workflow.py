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
            "run: git diff --exit-code -- bindings/rust/abi/StateOracle.json"
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
            "  release-cargo-verify:\n", 1
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
            "  release-cargo-verify:\n", 1
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

    def test_cargo_verification_has_no_oidc_permission(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        verify_job = workflow.split("  release-cargo-verify:\n", 1)[1].split(
            "  release-cargo:\n", 1
        )[0]

        self.assertIn("needs: create-artifacts", verify_job)
        self.assertIn("contents: read", verify_job)
        self.assertNotIn("id-token: write", verify_job)
        self.assertIn("uses: actions/checkout@", verify_job)
        self.assertIn("uses: actions/download-artifact@", verify_job)
        self.assertIn("name: credible-layer-contracts-artifacts", verify_job)
        self.assertIn("cmp -s artifacts/StateOracle.json", verify_job)
        self.assertIn(
            "cargo publish --manifest-path bindings/rust/Cargo.toml --dry-run",
            verify_job,
        )
        self.assertIn("id: published", verify_job)
        self.assertIn("exists: ${{ steps.published.outputs.exists }}", verify_job)
        self.assertNotIn("rust-lang/crates-io-auth-action", verify_job)

    def test_cargo_publish_job_is_minimal(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        release_job = workflow.split("  release-cargo:\n", 1)[1].split(
            "  release-github:\n", 1
        )[0]

        self.assertIn("needs: release-cargo-verify", release_job)
        self.assertIn(
            "if: needs.release-cargo-verify.outputs.exists != 'true'", release_job
        )
        self.assertIn("id-token: write", release_job)
        self.assertIn("uses: actions/checkout@", release_job)
        self.assertIn("uses: rust-lang/crates-io-auth-action@", release_job)
        self.assertIn(
            "CARGO_REGISTRY_TOKEN: ${{ steps.crates-io-auth.outputs.token }}",
            release_job,
        )
        self.assertIn(
            "run: cargo publish --manifest-path bindings/rust/Cargo.toml --no-verify",
            release_job,
        )
        for verification_step in (
            "rustup toolchain install",
            "cargo fmt",
            "cargo clippy",
            "cargo test",
            "--dry-run",
            "actions/download-artifact",
            "cmp -s",
            "curl",
        ):
            self.assertNotIn(verification_step, release_job)

    def test_cargo_release_actions_are_pinned_to_commit_shas(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        cargo_jobs = workflow.split("  release-cargo-verify:\n", 1)[1].split(
            "  release-github:\n", 1
        )[0]
        action_references = [
            line.strip()
            for line in cargo_jobs.splitlines()
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

    def test_cargo_and_npm_packages_share_release_version(self):
        package = json.loads((ROOT / "package.json").read_text())
        with (ROOT / "bindings" / "rust" / "Cargo.toml").open("rb") as manifest:
            cargo_package = tomllib.load(manifest)["package"]

        self.assertEqual(cargo_package["name"], "credible-layer-contracts")
        self.assertEqual(cargo_package["version"], package["version"])
        self.assertEqual(cargo_package["publish"], ["crates-io"])
        self.assertEqual(cargo_package["license"], "MIT OR Apache-2.0")

    def test_cargo_package_includes_repository_license_texts(self):
        crate_root = ROOT / "bindings" / "rust"
        with (crate_root / "Cargo.toml").open("rb") as manifest:
            included_files = tomllib.load(manifest)["package"]["include"]

        for license_name in ("LICENSE-MIT", "LICENSE-APACHE"):
            self.assertIn(license_name, included_files)
            self.assertEqual(
                (crate_root / license_name).read_text().splitlines(),
                (ROOT / license_name).read_text().splitlines(),
            )

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
        self.assertIn('cp "${ARTIFACTS}/StateOracle.json"', script)

    def test_package_requests_provenance(self):
        package = json.loads((ROOT / "package.json").read_text())

        self.assertEqual(package["publishConfig"]["access"], "public")
        self.assertIs(package["publishConfig"]["provenance"], True)


if __name__ == "__main__":
    unittest.main()
