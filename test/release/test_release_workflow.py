import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ReleaseWorkflowTest(unittest.TestCase):
    def test_npm_publish_runs_in_the_trusted_caller_workflow(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()
        release_job = workflow.split("  release-npm:\n", 1)[1].split(
            "  release-github:\n", 1
        )[0]

        self.assertIn("id-token: write", release_job)
        self.assertIn("runs-on: ubuntu-latest", release_job)
        self.assertIn("uses: phylaxsystems/actions/release-npm@main", release_job)
        self.assertNotIn(
            "uses: phylaxsystems/actions/.github/workflows/release-npm.yaml",
            release_job,
        )

    def test_existing_tag_can_be_retried_without_rewriting_it(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text()

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("release_tag:", workflow)
        self.assertIn("ref: ${{ inputs.release_tag || github.ref }}", workflow)
        self.assertIn("release_tag: ${{ inputs.release_tag }}", workflow)
        self.assertIn("if: github.event_name == 'push'", workflow)

    def test_package_requests_provenance(self):
        package = json.loads((ROOT / "package.json").read_text())

        self.assertEqual(package["publishConfig"]["access"], "public")
        self.assertIs(package["publishConfig"]["provenance"], True)


if __name__ == "__main__":
    unittest.main()
