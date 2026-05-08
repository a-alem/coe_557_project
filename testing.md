# Testing Documentation - COE 557 Project

## Purpose
This document defines the validation procedures for the SDN dynamic access-control controller, including control-plane startup, data-plane policy enforcement, REST API behavior, and policy-logic regression checks.

## Scope
The tests in this document verify the behavior implemented in:
- `iot_acl_controller_ryu.py`
- `controller/` modules (`app.py`, `policy.py`, `openflow.py`, `rest.py`)
- `docker-compose.yml`

## System Under Test
- SDN controller: Ryu (OpenFlow 1.3)
- Data-plane switch: Open vSwitch (via Mininet)
- Topology: single switch, four hosts (`h1`, `h2`, `h3`, `h4`)
- Protected server: `h4` / `10.0.0.4`
- REST API: `http://127.0.0.1:8080`

## API Endpoints Covered
- `GET /state`
- `GET /acl`
- `POST /acl/block`
- `POST /acl/allow`
- `GET /token`
- `POST /token/create`
- `POST /token/revoke`
- `POST /auth/login`
- `POST /auth/logout`

## Prerequisites
From repository root:
```bash
cd <repo-root>
```

Install required tools (if missing):
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch curl jq
```

Clean stale Mininet state:
```bash
sudo mn -c
```

## Test Environment Startup

### A) Controller startup (Docker)
```bash
docker compose up -d --build
docker compose logs -f ryu-controller
```

Expected:
1. controller starts without crash
2. controller waits for switch connection

### B) Controller startup (direct Python)
```bash
ryu-manager iot_acl_controller_ryu.py
```

Expected:
1. controller starts and binds ports
2. no import/runtime failure

### C) Mininet topology startup
```bash
sudo mn --topo single,4 \
  --controller remote,ip=127.0.0.1,port=6653 \
  --switch ovsk,protocols=OpenFlow13
```

Inside Mininet, verify host IP assignment:
```bash
h1 ifconfig h1-eth0
h2 ifconfig h2-eth0
h3 ifconfig h3-eth0
h4 ifconfig h4-eth0
```

Expected:
1. `h4` has `10.0.0.4`

## Functional Test Cases

### T1 - Default block policy for unauthenticated hosts
Inside Mininet:
```bash
h1 ping -c 3 h4
h2 ping -c 3 h4
h3 ping -c 3 h4
```

Expected:
1. all pings fail prior to authentication/allow
2. controller logs include blocked-host decisions

### T2 - OpenFlow rule installation visibility
From Mininet CLI:
```bash
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Expected:
1. table-miss rule exists
2. drop flows are present for blocked `src -> 10.0.0.4`

### T3 - Initial REST state
```bash
curl -s http://127.0.0.1:8080/state | jq
```

Expected:
1. `authenticated_hosts` is empty
2. token list is empty before token creation
3. ACL sets are present

### T4 - Token creation
```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/token/create | jq -r '.token')
echo "$TOKEN"
```

Expected:
1. non-empty token returned
2. token appears in `GET /state` / `GET /token`

### T5 - Successful host authentication (bind token to h1)
```bash
curl -s -X POST http://127.0.0.1:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"ip\":\"10.0.0.1\",\"token\":\"$TOKEN\"}" | jq
```

Expected:
1. `authenticated: true`
2. response confirms authentication/binding

### T6 - Access after authentication
Inside Mininet:
```bash
h1 ping -c 3 h4
h2 ping -c 3 h4
h3 ping -c 3 h4
```

Expected:
1. `h1 -> h4` succeeds
2. `h2 -> h4` remains blocked
3. `h3 -> h4` remains blocked

### T7 - Token reuse prevention
Attempt to reuse same token from a different host:
```bash
curl -s -X POST http://127.0.0.1:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"ip\":\"10.0.0.2\",\"token\":\"$TOKEN\"}" | jq
```

Expected:
1. `authenticated: false`
2. error indicates token already bound to another host

### T8 - Manual allow rule
```bash
curl -s -X POST http://127.0.0.1:8080/acl/allow \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.0.2"}' | jq
```

Then inside Mininet:
```bash
h2 ping -c 3 h4
```

Expected:
1. `h2 -> h4` succeeds without token login

### T9 - Manual block precedence
```bash
curl -s -X POST http://127.0.0.1:8080/acl/block \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.0.1"}' | jq
```

Then inside Mininet:
```bash
h1 ping -c 3 h4
```

Expected:
1. `h1 -> h4` fails after block
2. block takes precedence over prior authentication

### T10 - Logout and token revoke
Logout:
```bash
curl -s -X POST http://127.0.0.1:8080/auth/logout \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.0.1"}' | jq
```

Revoke:
```bash
curl -s -X POST http://127.0.0.1:8080/token/revoke \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\"}" | jq
```

Expected:
1. logout removes active host authentication
2. revoke removes token from token store

### T11 - Final consistency check
```bash
curl -s http://127.0.0.1:8080/state | jq
```

Expected:
1. state matches performed ACL/auth/token operations
2. no stale authenticated mapping for revoked/logged-out entities

## Regression Tests (Refactor Safety)
Run unit tests:
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Expected:
1. all tests pass
2. policy transitions remain consistent after refactor

## Cleanup
Stop Mininet and remove stale state:
```bash
sudo mn -c
```

If using Docker:
```bash
docker compose down
```

## Troubleshooting
If Mininet switch does not connect to controller:
```bash
sudo mn -c
sudo lsof -i :6653
```

If REST API is unreachable:
```bash
docker compose ps
docker compose logs --tail=100 ryu-controller
curl -s http://127.0.0.1:8080/state
```

If flow state appears stale:
```bash
sudo mn -c
sudo ovs-vsctl show
```

If local Python runtime has dependency mismatch (e.g., `eventlet`):
1. use Docker execution path (`docker compose up -d --build`)
2. or run with a compatible Python environment
