#!/usr/bin/env python3

import errno
import os
import pty
import selectors
import signal
import tempfile
import time
import unittest
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]
WIZARD = ROOT_DIR / "shell" / "deploy_wizard.sh"


class WizardSession:
    def __init__(self, no_color=True, balance_wei="0"):
        self._temporary_directory = tempfile.TemporaryDirectory()
        fake_bin = Path(self._temporary_directory.name)
        self.forge_arguments = fake_bin / "forge-arguments"
        forge = fake_bin / "forge"
        forge.write_text(
            '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$FAKE_FORGE_ARGUMENTS"\n'
        )
        forge.chmod(0o755)
        jq = fake_bin / "jq"
        jq.write_text("#!/bin/sh\nexit 0\n")
        jq.chmod(0o755)
        cast = fake_bin / "cast"
        cast.write_text(
            f"""#!/bin/sh
case "$1" in
    chain-id) echo 31337 ;;
    to-check-sum-address) echo "$2" ;;
    balance) echo {balance_wei} ;;
    nonce) echo 0 ;;
    wallet)
        case "$2" in
            list) echo "deployer (Local)" ;;
            address) echo 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 ;;
        esac
        ;;
esac
"""
        )
        cast.chmod(0o755)

        self.pid, self.master_fd = pty.fork()
        if self.pid == 0:
            environment = os.environ.copy()
            if no_color:
                environment["NO_COLOR"] = "1"
            else:
                environment.pop("NO_COLOR", None)
                environment["TERM"] = "xterm-256color"
            environment["RPC_URL"] = "http://rpc.example"
            environment["STATE_ORACLE_MAX_ASSERTIONS_PER_AA"] = "5"
            environment["STATE_ORACLE_ASSERTION_TIMELOCK_BLOCKS"] = "10"
            environment["STATE_ORACLE_ADMIN_ADDRESS"] = (
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            )
            environment["FAKE_FORGE_ARGUMENTS"] = str(self.forge_arguments)
            environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
            os.chdir(ROOT_DIR)
            os.execvpe(str(WIZARD), [str(WIZARD)], environment)

        self.output = ""
        self.transcript = ""
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.master_fd, selectors.EVENT_READ)

    def expect_any(self, *needles, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for needle in needles:
                if needle in self.output:
                    match_end = self.output.index(needle) + len(needle)
                    self.output = self.output[match_end:]
                    return needle

            if not self.selector.select(0.1):
                continue
            try:
                chunk = os.read(self.master_fd, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            decoded = chunk.decode(errors="replace")
            self.output += decoded
            self.transcript += decoded

        self.fail_with_output(f"Timed out waiting for one of: {needles}")

    def send(self, keys):
        os.write(self.master_fd, keys)

    def fail_with_output(self, message):
        raise AssertionError(f"{message}\nWizard output:\n{self.output}")

    def close(self):
        try:
            os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.selector.close()
        try:
            os.close(self.master_fd)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except ChildProcessError:
            pass
        self._temporary_directory.cleanup()


class DeployWizardTest(unittest.TestCase):
    def test_interactive_output_uses_color(self):
        wizard = WizardSession(no_color=False)
        try:
            wizard.expect_any("Credible Layer deployment wizard")
            self.assertIn("\x1b[1m\x1b[36m", wizard.transcript)
        finally:
            wizard.close()

    def test_assigning_multiple_da_verifiers_to_production_advances_to_whitelist(self):
        wizard = WizardSession()
        try:
            wizard.expect_any("What kind of deployment is this?")
            wizard.send(b"\r")
            wizard.expect_any("Deploy a staging State Oracle as well?")
            wizard.send(b"\r")

            wizard.expect_any("Which admin verifiers should be deployed?")
            wizard.send(b" \r")
            wizard.expect_any("Add Owner to which State Oracle(s)?")
            wizard.send(b" \r")

            wizard.expect_any("Which DA verifiers should be deployed?")
            wizard.send(b" \x1b[B \r")
            wizard.expect_any("Add ECDSA signatures to which State Oracle(s)?")
            wizard.send(b" \r")
            wizard.expect_any("Add On-chain bytecode to which State Oracle(s)?")
            wizard.send(b" \r")
            wizard.expect_any("Should the State Oracle whitelist be enabled?")
        finally:
            wizard.close()

    def test_zero_balance_wallet_stops_before_forge(self):
        wizard = WizardSession()
        try:
            wizard.expect_any("What kind of deployment is this?")
            wizard.send(b"\r")
            wizard.expect_any("Deploy a staging State Oracle as well?")
            wizard.send(b"\r")

            wizard.expect_any("Which admin verifiers should be deployed?")
            wizard.send(b" \r")
            wizard.expect_any("Add Owner to which State Oracle(s)?")
            wizard.send(b" \r")

            wizard.expect_any("Which DA verifiers should be deployed?")
            wizard.send(b"\x1b[B \r")
            wizard.expect_any("Add On-chain bytecode to which State Oracle(s)?")
            wizard.send(b" \r")

            wizard.expect_any("Should the State Oracle whitelist be enabled?")
            wizard.send(b"\x1b[B\r")
            wizard.expect_any("Verify deployed contracts on the block explorer?")
            wizard.send(b"\x1b[B\r")

            wizard.expect_any("RPC URL")
            wizard.send(b"\r")
            wizard.expect_any("Maximum assertions per adopter")
            wizard.send(b"\r")
            wizard.expect_any("Assertion timelock in blocks")
            wizard.send(b"\r")
            wizard.expect_any("State Oracle admin")
            wizard.send(b"\r")

            wizard.expect_any("Which Foundry wallet should deploy the contracts?")
            wizard.send(b"\r")
            wizard.expect_any("Password for deployer")
            wizard.send(b"password\r")

            result = wizard.expect_any(
                "has no funds on chain 31337",
                "Deployment summary",
            )
            if result == "Deployment summary":
                self.fail("zero-balance wallet reached the deployment confirmation")
        finally:
            wizard.close()

    def test_funded_account_sets_forge_rpc_and_sender(self):
        wizard = WizardSession(balance_wei="1000000000000000000")
        try:
            wizard.expect_any("What kind of deployment is this?")
            wizard.send(b"\r")
            wizard.expect_any("Deploy a staging State Oracle as well?")
            wizard.send(b"\r")

            wizard.expect_any("Which admin verifiers should be deployed?")
            wizard.send(b" \r")
            wizard.expect_any("Add Owner to which State Oracle(s)?")
            wizard.send(b" \r")

            wizard.expect_any("Which DA verifiers should be deployed?")
            wizard.send(b"\x1b[B \r")
            wizard.expect_any("Add On-chain bytecode to which State Oracle(s)?")
            wizard.send(b" \r")

            wizard.expect_any("Should the State Oracle whitelist be enabled?")
            wizard.send(b"\x1b[B\r")
            wizard.expect_any("Verify deployed contracts on the block explorer?")
            wizard.send(b"\x1b[B\r")

            wizard.expect_any("RPC URL")
            wizard.send(b"\r")
            wizard.expect_any("Maximum assertions per adopter")
            wizard.send(b"\r")
            wizard.expect_any("Assertion timelock in blocks")
            wizard.send(b"\r")
            wizard.expect_any("State Oracle admin")
            wizard.send(b"\r")

            wizard.expect_any("Which Foundry wallet should deploy the contracts?")
            wizard.send(b"\r")
            wizard.expect_any("Password for deployer")
            wizard.send(b"password\r")

            wizard.expect_any("Ready to continue?")
            self.assertIn("--rpc-url \\<configured\\>", wizard.transcript)
            wizard.send(b"\r")
            wizard.expect_any("Deployment complete", "broadcast receipt was not found")

            forge_arguments = wizard.forge_arguments.read_text().splitlines()
            rpc_index = forge_arguments.index("--rpc-url")
            self.assertEqual(forge_arguments[rpc_index + 1], "http://rpc.example")
            sender_index = forge_arguments.index("--sender")
            self.assertEqual(
                forge_arguments[sender_index + 1],
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            )
        finally:
            wizard.close()


if __name__ == "__main__":
    unittest.main()
