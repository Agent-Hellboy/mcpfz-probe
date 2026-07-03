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


if __name__ == "__main__":
    unittest.main()

