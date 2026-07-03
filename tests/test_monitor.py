import unittest

from mcpfz_probe import FakeRuntimeMonitor, RuntimeEvent


class FakeRuntimeMonitorTests(unittest.TestCase):
    def test_attributes_events_recorded_during_active_call(self) -> None:
        monitor = FakeRuntimeMonitor()
        monitor.start()
        monitor.begin_call("call-1", "tool")
        monitor.record(RuntimeEvent(type="exec", pid=123, data={"argv": ["/bin/sh"]}))
        summary = monitor.end_call("call-1")

        self.assertEqual(summary.counts, {"exec": 1})
        self.assertEqual(summary.events[0].call_id, "call-1")
        self.assertEqual(summary.compact()["notable"][0]["argv"], ["/bin/sh"])

    def test_keeps_outside_call_events_ambient(self) -> None:
        monitor = FakeRuntimeMonitor([RuntimeEvent(type="connect", data={"dst": "127.0.0.1:9"})])
        monitor.start()

        self.assertEqual(len(monitor.ambient_events()), 1)
        self.assertEqual(monitor.ambient_events()[0].bucket, "ambient")


if __name__ == "__main__":
    unittest.main()

