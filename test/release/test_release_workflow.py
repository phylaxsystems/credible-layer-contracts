import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTest(unittest.TestCase):
    def test_npm_publish_runs_inline_in_the_trusted_workflow(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        release_job = workflow.split("  release-npm:\n", 1)[1].split(
            "  release-github:\n", 1
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

    def test_package_requests_provenance(self):
        package = json.loads((ROOT / "package.json").read_text())

        self.assertEqual(package["publishConfig"]["access"], "public")
        self.assertIs(package["publishConfig"]["provenance"], True)


if __name__ == "__main__":
    unittest.main()
