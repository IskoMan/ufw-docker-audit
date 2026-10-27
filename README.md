# UFW did not protect our Docker ports

A home server ran UFW with "default deny incoming, allow only the VPN interface". Its documentation said the server was closed to the home network. It was not: seven Docker-published ports answered any device on the LAN. This repo is the write-up and the small read-only script that finds the same problem on any host.

## The finding

On 2026-10-02 I probed the server's LAN address from another machine on the same network. Seven ports answered, although UFW was active and only allowed the VPN interface and loopback:

| What was listening | Response from the LAN |
|---|---|
| a sync database | 401 (login prompt reachable) |
| a git server | 200 |
| a media-download API | 200, no authentication |
| a file-sharing app | 302 to its login page |
| a git SSH port, a 3D-printer UI and its API | port open |

The WAN was never exposed: the router's NAT has no forwards. The risk was any device on the home network, such as guests or IoT devices, reaching admin interfaces that were meant to be VPN-only, one of them with no login at all.

## Why UFW did not apply

UFW writes its rules into the `INPUT` chain. A port published with `ports: ["3000:3000"]` binds `0.0.0.0` (and `::`), and Docker reaches it with a DNAT rule in the `nat` table. After DNAT the packet is addressed to the container, so the kernel routes it through `FORWARD`, not `INPUT`, and the UFW rules never see it. `ufw status` keeps showing "deny", which is why nobody noticed.

Containers with `network_mode: host` are different: they listen on the host itself, their traffic goes through `INPUT`, and UFW does filter them. I confirmed that on the same server: a host-network service bound to all interfaces timed out from the LAN.

## The fix

1. Every published port binds loopback: `"127.0.0.1:3000:3000"`. Nothing outside the host can reach it.
2. The VPN (Tailscale) forwards each needed port to loopback (`tailscale serve --tcp <port> tcp://127.0.0.1:<port>`), so clients on the VPN use the same name and port as before and no URL changed.
3. A rule for every new stack: never publish on `0.0.0.0`.

The other common fix is DROP rules in Docker's `DOCKER-USER` chain. I chose loopback binds because each one is visible in the compose file it belongs to, and a forgotten firewall rule fails open while a forgotten bind fails closed.

## Before and after

| | Before (2026-10-02) | After (re-measured 2026-10-27) |
|---|---|---|
| Ports bound `0.0.0.0` | 7 | 0 (19 published ports, all `127.0.0.1`) |
| Answering from the LAN | 7 of 7 | 0 of 7 (all time out; the host answers ping) |
| Reachable over the VPN | yes | yes, all 7 |

The "after" column is the output of the script below: `audit` on the server and `probe` from a second machine on the same LAN.

## The script

`ufw_docker_audit.py`, Python 3 standard library only, read-only, no root.

```
# on the Docker host: how is each published port bound?
./ufw_docker_audit.py audit            # exit 1 if any port bypasses UFW
./ufw_docker_audit.py audit --json > ports.json

# from another machine on the same network: does it actually answer?
./ufw_docker_audit.py probe 192.0.2.10 --from-json ports.json
./ufw_docker_audit.py probe 192.0.2.10 3000,8080
```

`audit` reads `docker inspect` and marks each binding `EXPOSED` (all interfaces), `BOUND` (one non-loopback address, still bypasses UFW on that interface), `loopback` or `host-network`. It also reads `"iptables"` from `daemon.json` and lists `DOCKER-USER` rules when it can; without root it says "not checked" instead of escalating. If it cannot list containers it says so and exits 2, never a false "0 exposed".

`probe` is the proof: a config can look right and still be wrong, so the last word is a TCP connect from where an attacker would stand.

Tests: `python3 -m unittest tests/test_audit.py`.

## Limits

- `audit` does not evaluate `DOCKER-USER` rules, only lists them. A host that filters there will still be reported `EXPOSED`; run `probe` to see the real result.
- `probe` tests TCP only and only from where you run it. Run it from each network that should not get in.
- Rootless Docker and rootless Podman publish through a userland port forwarder, not DNAT; there UFW does apply, and `audit` will over-report.

## What I took from it

The firewall doc was written from the config, not from a measurement. The check that caught it was a connect from a second machine, which is the one thing the tool keeps.
