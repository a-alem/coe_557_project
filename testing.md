# Testing Guide - COE 557 Project (SDN Dynamic Access Control for IoT)

This file is your practical test plan for demo/interview.

It is based on the actual project files:
- `iot_acl_controller_ryu.py`
- `docker-compose.yml`
- `README.md`

## 1) What You Are Proving

1. Controller connects to OVS using OpenFlow 1.3.
2. Default policy blocks unauthenticated IoT hosts from cloud server (`10.0.0.4`).
3. REST APIs work for ACL and token-based authentication.
4. Token binding rules are enforced (one token cannot be reused by another IP).
5. Flow rules are installed/removed dynamically when policy changes.

## 2) Quick Architecture Reminder

Topology in Mininet:
- `h1`, `h2` authorized-capable IoT hosts
- `h3` unauthorized test host
- `h4` cloud server (`10.0.0.4`)
- single OVS switch `s1`

Controller behavior:
- table-miss sends unknown traffic to controller
- if packet destination is cloud server:
1. allow only if source IP is authenticated or manually allowed
2. otherwise install DROP flow and block

REST APIs (port `8080`):
- `GET /state`
- `GET /acl`
- `POST /acl/block`
- `POST /acl/allow`
- `GET /token`
- `POST /token/create`
- `POST /token/revoke`
- `POST /auth/login`
- `POST /auth/logout`

## 3) Pre-Flight Checks

Run from project root:
```bash
cd <repo-root>
```

Install runtime tools if missing:
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch curl jq
```

Cleanup stale Mininet state:
```bash
sudo mn -c
```

## 4) Start Controller

Option A (Docker, recommended for this repo)
```bash
docker compose up -d --build
docker compose logs -f ryu-controller
```

Option B (direct Python venv)
```bash
ryu-manager iot_acl_controller_ryu.py
```

Pass criteria:
1. controller process is running
2. no startup crash
3. waits for switch connection

## 5) Start Mininet Test Topology

In a second terminal:
```bash
sudo mn --topo single,4 \
  --controller remote,ip=127.0.0.1,port=6653 \
  --switch ovsk,protocols=OpenFlow13
```

Inside Mininet verify host IPs:
```bash
h1 ifconfig h1-eth0
h2 ifconfig h2-eth0
h3 ifconfig h3-eth0
h4 ifconfig h4-eth0
```

Expected cloud server IP in your code: `10.0.0.4`.

## 6) Core Data-Plane Tests

## Test T1 - Unauthenticated hosts are blocked

Inside Mininet:
```bash
h1 ping -c 3 h4
h2 ping -c 3 h4
h3 ping -c 3 h4
```

Expected:
1. all blocked/fail before auth
2. controller logs show blocked messages

Explain:
- Default zero-trust behavior. No authentication means no access to cloud.

## Test T2 - Flow table shows policy rules

From Mininet CLI:
```bash
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Expected:
1. table-miss rule exists
2. drop rules appear for blocked source IPs toward `10.0.0.4`

Explain:
- Controller converts high-level policy into switch flow entries.

## 7) REST API Functional Tests

Use a third terminal on same host.

## Test T3 - Check initial state
```bash
curl -s http://127.0.0.1:8080/state | jq
```

Expected:
1. `authenticated_hosts` empty
2. `tokens` empty (before creation)
3. ACL sets visible

## Test T4 - Create token
```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/token/create | jq -r '.token')
echo "$TOKEN"
```

Expected:
1. valid UUID token returned

## Test T5 - Login h1 with token
```bash
curl -s -X POST http://127.0.0.1:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"ip\":\"10.0.0.1\",\"token\":\"$TOKEN\"}" | jq
```

Expected:
1. `authenticated: true`
2. message indicates token bound/authenticated

## Test T6 - Verify h1 now allowed

Back in Mininet:
```bash
h1 ping -c 3 h4
h2 ping -c 3 h4
h3 ping -c 3 h4
```

Expected:
1. `h1 -> h4` works
2. `h2 -> h4` still blocked
3. `h3 -> h4` still blocked

Explain:
- Authentication is per-host IP binding, not global allow.

## Test T7 - Token reuse prevention

Try reusing the same token for another host:
```bash
curl -s -X POST http://127.0.0.1:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"ip\":\"10.0.0.2\",\"token\":\"$TOKEN\"}" | jq
```

Expected:
1. HTTP/auth failure (`authenticated: false`)
2. message: token already bound to another host

Explain:
- Prevents token sharing/replay across hosts.

## Test T8 - Manual ACL allow for h2
```bash
curl -s -X POST http://127.0.0.1:8080/acl/allow \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.0.2"}' | jq
```

Then in Mininet:
```bash
h2 ping -c 3 h4
```

Expected:
1. h2 becomes allowed even without token login

Explain:
- `manual_allowed_ips` overrides default unauthenticated block.

## Test T9 - Manual ACL block h1 (even if authenticated)
```bash
curl -s -X POST http://127.0.0.1:8080/acl/block \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.0.1"}' | jq
```

Then in Mininet:
```bash
h1 ping -c 3 h4
```

Expected:
1. h1 blocked now

Explain:
- Block list has highest policy priority in app logic.

## Test T10 - Logout and revoke

Logout h1:
```bash
curl -s -X POST http://127.0.0.1:8080/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.0.1"}' | jq
```

Revoke token:
```bash
curl -s -X POST http://127.0.0.1:8080/token/revoke \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\"}" | jq
```

Expected:
1. host logout forces block rule again
2. token removed from token store

## 8) Final State Validation

```bash
curl -s http://127.0.0.1:8080/state | jq
```

Verify consistency:
1. token map reflects revocation
2. authenticated host map reflects logout
3. ACL sets reflect block/allow operations you did

## 9) What to Explain While Testing

Use this 4-step speaking pattern per test:
1. Goal: what security behavior I am validating.
2. Command: what I execute.
3. Output: what confirms pass/fail.
4. Concept: why that behavior matters in SDN/NFV security.

Example line:
- "Now I run `/auth/login` for `h1`; if token binding succeeds, the controller removes the drop rule for `10.0.0.1 -> 10.0.0.4`, so `h1` can ping the cloud server."

## 10) Quick Troubleshooting

If Mininet cannot connect controller:
```bash
sudo mn -c
sudo lsof -i :6653
```

If API not reachable:
```bash
docker compose ps
docker compose logs --tail=100 ryu-controller
curl -s http://127.0.0.1:8080/state
```

If flows look stale:
```bash
sudo mn -c
sudo ovs-vsctl show
```

If direct run fails due Python/eventlet mismatch:
- use Docker path for stable execution (`python:3.9-slim` in this repo).

## 11) Refactor Regression Test (Unit)

Run:
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Expected:
1. all policy tests pass
2. token/auth/ACL logic remains stable after refactor

## 12) Demo-Ready Minimal Script (Fast)

Run these in order for a short live demo:
```bash
# terminal 1
cd ~/coe_557_project
docker compose up -d --build
docker compose logs -f ryu-controller
```

```bash
# terminal 2
sudo mn -c
sudo mn --topo single,4 --controller remote,ip=127.0.0.1,port=6653 --switch ovsk,protocols=OpenFlow13
# in mininet
h1 ping -c 2 h4
```

```bash
# terminal 3
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/token/create | jq -r '.token')
curl -s -X POST http://127.0.0.1:8080/auth/login -H 'Content-Type: application/json' -d "{\"ip\":\"10.0.0.1\",\"token\":\"$TOKEN\"}" | jq
curl -s http://127.0.0.1:8080/state | jq
```

Back to Mininet:
```bash
h1 ping -c 2 h4
h2 ping -c 2 h4
h3 ping -c 2 h4
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

This sequence usually demonstrates the project clearly in less than 5 minutes.
