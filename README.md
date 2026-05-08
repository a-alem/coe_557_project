# 🛜 SDN Based Dynamic Access Control for IoT Networks
This project focuses on improving IoT network security using Software Defined Networking (SDN). Traditional IoT networks rely on static configurations, which makes it difficult to detect and block unauthorized devices in real time.

To address this, we designed a system where a centralized SDN controller dynamically controls network traffic using programmable rules.

We implemented the system using:
- Mininet for network simulation
- Open vSwitch as the SDN switch
- Ryu controller for implementing access control logic

Our network consists of:
- Two authorized IoT devices (h1, h2)
- One unauthorized device (h3)
- One cloud server (h4)

The controller enforces a simple Access Control List (ACL):
- Authorized devices are allowed to communicate with the server
- Unauthorized devices are automatically blocked

When a device sends traffic:
- The switch forwards unknown packets to the controller
- The controller checks the policy, it then installs a rule to either allow or drop the traffic

# 🛠️ Installation
An amd64 AWS EC2 instance running Ubuntu22.04 was used to deploy this project, more can be found in the `/terraform` directory which holds all infrastructure related configurations

## 🎨 Simplified Diagram
          +----------------------+
          |   SDN Controller     |
          |   (Ryu - Control)    |
          +----------+-----------+
                     |
          OpenFlow (control channel)
                     |
             +-------+--------+
             |   SDN Switch   |
             | (Open vSwitch) |
             +---+---+---+----+
                 |   |   |
                h1  h2  h3        h4
             (IoT)(IoT)(Bad)   (Server)

## ⚙️ Installation Steps
Install required packages:
```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y net-tools iproute2 tcpdump wireshark-common
sudo apt install -y mininet openvswitch-switch openvswitch-common
```

Test that Mininet works properly, Mininet should creates a small topology and hosts can ping each other with this command to test things out.
```bash
sudo mn --test pingall
```

Clear Mininet configs for clean spin-up later
```bash
sudo mn -c
```

Installing Ryu on Python3.10+ introduces some compatibility issues, especially with `eventlet`. Safest bet is to use Python3.9 or older

Below is the steps needed to install Python3.9 (if your Python version is 3.10 or later, otherwise skip this)
```bash
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.9 python3.9-venv python3.9-dev build-essential
```

Create virtual env for Python3.9 and activate it to avoid package issues with your global Python installation
```bash
python3.9 -m venv ~/ryu-venv
source ~/ryu-venv/bin/activate
pip install "pip==23.3.2" "setuptools==67.6.1" wheel
pip install --no-build-isolation eventlet==0.30.2
pip install --no-build-isolation ryu==4.34
```

Finally, to verify that Ryu was installed correctly, run the following:
```bash
ryu-manager --version
```

# 💿 Running The Project
Clone this repository, and change directory into it after activating your virtual env (if needed), then run the following:
```bash
ryu-manager iot_acl_controller_ryu.py
```

In another terminal (of the same host), run the following:
```bash
sudo mn --topo single,4 \
  --controller remote,ip=127.0.0.1,port=6653 \
  --switch ovsk,protocols=OpenFlow13
```

Inside Mininet, you can run the following:
```bash
h1 ping -c 3 h4
h2 ping -c 3 h4
h3 ping -c 3 h4
```

The expected behavior should be, as these hosts are not **authenticated** yet:
```
h1 -> h4: blocked
h2 -> h4: blocked
h3 -> h4: blocked
```

You can view the installed policies in the switch by OpenFlow (Through the Ryu controller) by running this command in a new third terminal of the same host:
```bash
sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

# 🧩 Testing
For testing related commands and overview, please check `testing.md` document

# 🎛️ HTTP REST Controllers
This project extends the typical Ryu controller flow with an additional WSGI implemented HTTP REST controller layer embedded into the Ryu controller itself.

The goal is to use these controllers and the APIs they expose to manage ACL rules and token authentication at runtime to extend the usability of Ryu.

By default, all hosts are **unauthenticated**, which means no host can access the network or connect to any host. Once a host is authenticated with a token, it can access resources in the network. ACL endpoints provide an additional way to permanently block or unblock a specific host entirely from accessing the network, even if the host was already authenticated with a token.

A given token cannot be used by more than one host at a time, securing the flow of connection and preventing spoofing and replay attacks.

The following controllers/APIs mapping are embedded into Ryu:
- `/acl`: Controller for ACL, the following are its endpoints
  - `POST /block`: blocks a given IP from accessing the network
  - `POST /allow`: unblock an already blocked IP
- `/token`: Controller for tokens, the following are its endpoints
  - `POST /create`: Creates an access token
  - `POST /revoke`: Revoke a given access token
- `/auth`: Controller for logging in using a token
  - `POST /login`: Bind an IP address to a token, resulting in a logged in host
- `GET /state`: Controller and sole endpoint for listing the current configurations, ACLs, and token-ip associations.

More details on the REST APIs with saved examples and payload structures are available in the POSTMAN collection of the project.