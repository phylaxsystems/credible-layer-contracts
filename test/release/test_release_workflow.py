import json
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTest(unittest.TestCase):
    def test_npm_publish_runs_inline_in_the_trusted_workflow(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        release_job = workflow.split("  release-npm:\n", 1)[1].split(
            "  release-cargo:\n", 1
        )[0]

        self.assertIn("id-token: write", release_job)
        self.assertIn("runs-on: ubuntu-latest", release_job)
        self.assertIn("uses: actions/checkout@", release_job)
        self.assertIn("uses: actions/setup-node@", release_job)
        self.assertIn("registry-url: https://registry.npmjs.org", release_job)
        self.assertIn("run: npm install -g npm@latest", release_job)
        self.assertIn("uses: actions/download-artifact@", release_job)
        self.assertIn("name: credible-layer-contracts-artifacts", release_job)
        self.assertIn("path: artifacts/", release_job)
        self.assertIn(
            "run: npm publish --access public --ignore-scripts=true", release_job
        )
        self.assertNotIn("phylaxsystems/actions/release-npm", release_job)

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
