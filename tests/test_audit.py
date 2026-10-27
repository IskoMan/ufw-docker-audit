import socket
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import ufw_docker_audit as uda


def container(name, ports=None, mode="bridge"):
    return {
        "Name": "/" + name,
        "HostConfig": {"NetworkMode": mode},
        "NetworkSettings": {"Ports": ports or {}},
    }


class Classify(unittest.TestCase):
    def test_all_interfaces_is_exposed(self):
        for ip in ("", "0.0.0.0", "::"):
            self.assertEqual(uda.classify_host_ip(ip), uda.EXPOSED)

    def test_loopback(self):
        for ip in ("127.0.0.1", "::1", "127.0.1.1"):
            self.assertEqual(uda.classify_host_ip(ip), uda.LOOPBACK)

    def test_specific_address_is_bound(self):
        self.assertEqual(uda.classify_host_ip("192.0.2.10"), uda.BOUND)


class Findings(unittest.TestCase):
    def test_before_and_after_the_fix(self):
        # The default `ports: ["3000:3000"]` publishes on 0.0.0.0 and [::].
        before = [
            container(
                "git",
                {
                    "3000/tcp": [
                        {"HostIp": "0.0.0.0", "HostPort": "3000"},
                        {"HostIp": "::", "HostPort": "3000"},
                    ]
                },
            )
        ]
        after = [
            container(
                "git", {"3000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "3000"}]}
            )
        ]
        self.assertEqual(
            {r["status"] for r in uda.findings_from_inspect(before)}, {uda.EXPOSED}
        )
        self.assertEqual(
            {r["status"] for r in uda.findings_from_inspect(after)}, {uda.LOOPBACK}
        )

    def test_unpublished_and_host_network(self):
        rows = uda.findings_from_inspect(
            [
                container(
                    "db", {"5432/tcp": None}
                ),  # EXPOSE in the image, not published
                container("cam", mode="host"),
            ]
        )
        self.assertEqual([r["status"] for r in rows], [uda.HOSTNET])


class Probe(unittest.TestCase):
    def test_open_and_refused(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]
        self.assertEqual(uda.probe_one("127.0.0.1", port, 1), "open")
        srv.close()
        self.assertEqual(uda.probe_one("127.0.0.1", port, 1), "refused")


if __name__ == "__main__":
    unittest.main()
