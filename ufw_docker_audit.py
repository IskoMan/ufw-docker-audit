#!/usr/bin/env python3
"""Find Docker-published ports that UFW does not filter.

Docker publishes a port with DNAT rules in the nat table, so the packet goes
through FORWARD, not INPUT. UFW's rules live in INPUT, so a port published on
0.0.0.0 answers the network even when `ufw status` says "deny incoming".

Two read-only subcommands, standard library only:

  audit   run on the Docker host: lists every published port and how it is bound
  probe   run from another machine: TCP-connects to those ports to prove reachability

Nothing is changed on any host. No root is needed; checks that need root
(DOCKER-USER chain) are reported as "not checked" instead of escalating.
"""

import argparse
import ipaddress
import json
import shutil
import socket
import subprocess
import sys

EXPOSED = "EXPOSED"  # all interfaces, bypasses UFW
BOUND = "BOUND"  # one specific non-loopback address, bypasses UFW on that interface
LOOPBACK = "loopback"  # 127.0.0.1 / ::1, not reachable from the network
HOSTNET = "host-network"  # network_mode: host, goes through INPUT, UFW applies


def run(cmd):
    """Run a command, return (exit code, stdout). Never raises on failure."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)
        return p.returncode, p.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def classify_host_ip(host_ip):
    if host_ip in ("", "0.0.0.0", "::"):
        return EXPOSED
    try:
        if ipaddress.ip_address(host_ip).is_loopback:
            return LOOPBACK
    except ValueError:
        pass
    return BOUND


def findings_from_inspect(containers):
    """Turn `docker inspect` output (a list of dicts) into one row per published port."""
    rows = []
    for c in containers:
        name = c.get("Name", "").lstrip("/")
        mode = (c.get("HostConfig") or {}).get("NetworkMode", "")
        if mode == "host":
            rows.append(
                {
                    "container": name,
                    "host_ip": "-",
                    "host_port": "-",
                    "container_port": "-",
                    "status": HOSTNET,
                }
            )
            continue
        ports = (c.get("NetworkSettings") or {}).get("Ports") or {}
        for cport, bindings in sorted(ports.items()):
            for b in bindings or []:  # None = exposed in the image but not published
                rows.append(
                    {
                        "container": name,
                        "host_ip": b.get("HostIp", ""),
                        "host_port": b.get("HostPort", ""),
                        "container_port": cport,
                        "status": classify_host_ip(b.get("HostIp", "")),
                    }
                )
    return rows


def docker_iptables_disabled():
    """True if daemon.json sets "iptables": false, False if true, None if unset or unreadable."""
    try:
        with open("/etc/docker/daemon.json") as f:
            v = json.load(f).get("iptables")
    except (OSError, ValueError):
        return None
    return (v is False) if isinstance(v, bool) else None


def docker_user_rules():
    """Rules in DOCKER-USER (the one chain Docker leaves to the admin), or None without root."""
    if not shutil.which("iptables"):
        return None
    code, out = run(["iptables", "-S", "DOCKER-USER"])
    if code != 0:
        return None
    return [
        ln
        for ln in out.splitlines()
        if not ln.startswith("-N") and "-j RETURN" not in ln
    ]


def audit(args):
    code, ufw = run(["systemctl", "is-active", "ufw"])
    report = {"host": socket.gethostname(), "ufw": ufw.strip() or "unknown"}

    code, ids = run(["docker", "ps", "-q"])
    if code != 0:
        report["docker"] = "not running or no access (needs the docker group)"
        report["ports"] = None
    else:
        ids = ids.split()
        containers = []
        if ids:
            code, out = run(["docker", "inspect", *ids])
            containers = json.loads(out) if code == 0 else []
        report["docker"] = f"{len(ids)} running containers"
        report["ports"] = findings_from_inspect(containers)

    report["docker_iptables_disabled"] = docker_iptables_disabled()
    rules = docker_user_rules()
    report["docker_user_rules"] = (
        rules if rules is not None else "not checked (needs root)"
    )

    exposed = [r for r in report["ports"] or [] if r["status"] in (EXPOSED, BOUND)]
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"host: {report['host']}   ufw: {report['ufw']}   docker: {report['docker']}"
        )
        print(f"DOCKER-USER rules: {report['docker_user_rules']}")
        if report["ports"]:
            print(
                f"\n{'STATUS':13} {'HOST IP':16} {'PORT':6} {'CONTAINER PORT':15} CONTAINER"
            )
            for r in sorted(
                report["ports"],
                key=lambda r: (r["status"] != EXPOSED, r["status"], r["container"]),
            ):
                print(
                    f"{r['status']:13} {r['host_ip'] or '*':16} {r['host_port']:6} "
                    f"{r['container_port']:15} {r['container']}"
                )
        if report["docker_iptables_disabled"]:
            print(
                '\ndaemon.json sets "iptables": false: Docker adds no DNAT rules here.'
            )
        if report["ports"] is None:
            print("\nNot checked: cannot list containers on this host.")
        else:
            print(f"\n{len(exposed)} published port(s) not covered by UFW.")
        if exposed:
            print(
                'Fix: publish on 127.0.0.1 ("127.0.0.1:8080:80") and reach it through a '
                "proxy or VPN, or add DROP rules to the DOCKER-USER chain."
            )
        if any(r["status"] == HOSTNET for r in report["ports"] or []):
            print(
                "host-network containers listen on the host itself: UFW does filter them."
            )
    if report["ports"] is None:
        return 2
    return 1 if exposed else 0


def probe_one(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "open"
    except TimeoutError:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except OSError as e:
        return f"error ({e.strerror or e})"


def probe(args):
    ports = set()
    for p in args.ports:
        ports.update(int(x) for x in p.split(",") if x)
    if args.from_json:
        with open(args.from_json) as f:
            for r in json.load(f).get("ports", []):
                if r["host_port"] not in ("", "-"):
                    ports.add(int(r["host_port"]))
    if not ports:
        sys.exit("probe: no ports given")
    opened = 0
    for port in sorted(ports):
        result = probe_one(args.host, port, args.timeout)
        opened += result == "open"
        print(f"{args.host}:{port:<6} {result}")
    print(f"\n{opened} of {len(ports)} port(s) answered.")
    return 1 if opened else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit", help="list published ports on this Docker host")
    a.add_argument(
        "--json", action="store_true", help="machine-readable output (feed it to probe)"
    )
    p = sub.add_parser(
        "probe", help="TCP-connect to a host's ports from another machine"
    )
    p.add_argument(
        "host", help="the Docker host's LAN address, not its VPN or loopback address"
    )
    p.add_argument("ports", nargs="*", help="ports, space or comma separated")
    p.add_argument(
        "--from-json", metavar="FILE", help="take the ports from `audit --json` output"
    )
    p.add_argument("--timeout", type=float, default=3.0)
    args = ap.parse_args(argv)
    return audit(args) if args.cmd == "audit" else probe(args)


if __name__ == "__main__":
    sys.exit(main())
