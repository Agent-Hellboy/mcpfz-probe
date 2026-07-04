import tempfile
import unittest
from pathlib import Path

from mcpfz_probe import RuntimeEvent, RuntimePolicy, evaluate_events


class RuntimePolicyTests(unittest.TestCase):
    def test_flags_exec_connect_sensitive_read_and_external_write(self) -> None:
        with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as tmpdir:
            policy = RuntimePolicy(workspace=Path(workspace), tmpdir=Path(tmpdir))
            events = [
                RuntimeEvent(type="exec", call_id="c1", data={"argv": ["/bin/sh"]}),
                RuntimeEvent(type="connect", call_id="c1", data={"dst": "203.0.113.7:443"}),
                RuntimeEvent(type="file_open", call_id="c1", data={"path": "/home/me/.ssh/id_ed25519", "flags": "O_RDONLY"}),
                RuntimeEvent(type="file_open", call_id="c1", data={"path": "/etc/cron.d/x", "flags": "O_CREAT|O_WRONLY"}),
            ]

            categories = [finding.category for finding in evaluate_events(events, policy)]

        self.assertEqual(
            categories,
            [
                "runtime.exec",
                "runtime.net_connect",
                "runtime.sensitive_read",
                "runtime.fs_write",
            ],
        )

    def test_flags_delete_chmod_and_ptrace(self) -> None:
        with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as tmpdir:
            policy = RuntimePolicy(workspace=Path(workspace), tmpdir=Path(tmpdir))
            events = [
                RuntimeEvent(type="file_delete", call_id="c1", data={"path": "/etc/passwd"}),
                RuntimeEvent(type="chmod", call_id="c1", data={"path": "/root/x.sh", "mode": "755"}),
                RuntimeEvent(type="ptrace", call_id="c1", data={"request": 0, "target_pid": 0}),
                # Deletion inside the workspace is allowed -> no finding.
                RuntimeEvent(type="file_delete", call_id="c1", data={"path": f"{workspace}/tmp.txt"}),
            ]

            categories = [finding.category for finding in evaluate_events(events, policy)]

        self.assertEqual(
            categories,
            ["runtime.fs_delete", "runtime.fs_chmod", "runtime.ptrace"],
        )


if __name__ == "__main__":
    unittest.main()

