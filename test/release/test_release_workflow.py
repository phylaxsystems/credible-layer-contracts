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

    def test_cargo_publish_runs_inline_with_trusted_publishing(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        release_job = workflow.split("  release-cargo:\n", 1)[1].split(
            "  release-github:\n", 1
        )[0]

        self.assertIn("needs: create-artifacts", release_job)
        self.assertIn("id-token: write", release_job)
        self.assertIn("uses: actions/checkout@", release_job)
        self.assertIn("uses: actions/download-artifact@", release_job)
        self.assertIn("name: credible-layer-contracts-artifacts", release_job)
        self.assertIn("cmp -s artifacts/StateOracle.json", release_job)
        self.assertIn(
            "cargo publish --manifest-path bindings/rust/Cargo.toml --dry-run",
            release_job,
        )
        self.assertIn("uses: rust-lang/crates-io-auth-action@v1", release_job)
        self.assertIn(
            "CARGO_REGISTRY_TOKEN: ${{ steps.crates-io-auth.outputs.token }}",
            release_job,
        )
        self.assertIn(
            "run: cargo publish --manifest-path bindings/rust/Cargo.toml",
            release_job,
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
