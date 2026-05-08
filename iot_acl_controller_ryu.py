import json
import time
import uuid

from webob import Response

from ryu.base import app_manager
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, arp, icmp
from ryu.ofproto import ofproto_v1_3


iot_instance_name = "iot_acl_token_app"


class IoTACLTokenController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(IoTACLTokenController, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}

        self.blocked_ips = set()
        self.manual_allowed_ips = set()

        # token -> {"active": bool, "bound_ip": None or "10.0.0.x"}
        self.tokens = {}

        # ip -> token
        self.authenticated_hosts = {}

        # ICMP return flow tracking:
        self.allowed_icmp_return_flows = set()

        wsgi = kwargs["wsgi"]
        wsgi.register(IoTRESTController, {iot_instance_name: self})

    # OpenFlow helpers
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        instructions = [
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )

        datapath.send_msg(mod)

    def delete_flow(self, datapath, match):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match,
        )

        datapath.send_msg(mod)

    def install_drop_rule_for_ip(self, ip):
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip,
            )

            self.add_flow(
                datapath=datapath,
                priority=100,
                match=match,
                actions=[],
                idle_timeout=0,
                hard_timeout=0,
            )

            self.logger.warning("Installed DROP rule for source IP: %s", ip)

    def remove_drop_rules_for_ip(self, ip):
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip,
            )

            self.delete_flow(datapath, match)

            self.logger.info("Removed DROP rule for source IP if present: %s", ip)

    def clear_all_flows_and_reinstall_table_miss(self):
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            # Delete all flows
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=parser.OFPMatch(),
            )
            datapath.send_msg(mod)

            # Reinstall table-miss rule
            actions = [
                parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER,
                    ofproto.OFPCML_NO_BUFFER,
                )
            ]

            self.add_flow(
                datapath=datapath,
                priority=0,
                match=parser.OFPMatch(),
                actions=actions,
            )

        self.logger.info("Cleared all flows and reinstalled table-miss rule")

    # Auth and token logic
    def create_token(self):
        token = str(uuid.uuid4())

        self.tokens[token] = {
            "active": True,
            "bound_ip": None,
        }

        return token

    def revoke_token(self, token):
        if token not in self.tokens:
            return False, "token not found"

        bound_ip = self.tokens[token]["bound_ip"]

        if bound_ip:
            self.authenticated_hosts.pop(bound_ip, None)
            self.install_drop_rule_for_ip(bound_ip)
            self.remove_return_flows_for_ip(bound_ip)

        del self.tokens[token]

        return True, "token revoked"

    def authenticate_host(self, ip, token):
        if token not in self.tokens:
            self.install_drop_rule_for_ip(ip)
            return False, "invalid token"

        token_record = self.tokens[token]

        if not token_record["active"]:
            self.install_drop_rule_for_ip(ip)
            return False, "token inactive"

        bound_ip = token_record["bound_ip"]

        if bound_ip is None:
            token_record["bound_ip"] = ip
            self.authenticated_hosts[ip] = token
            self.blocked_ips.discard(ip)
            self.remove_drop_rules_for_ip(ip)

            return True, "host authenticated and token bound"

        if bound_ip == ip:
            self.authenticated_hosts[ip] = token
            self.blocked_ips.discard(ip)
            self.remove_drop_rules_for_ip(ip)

            return True, "host already authenticated"

        self.install_drop_rule_for_ip(ip)

        return False, "token already bound to another host"

    def logout_host(self, ip):
        token = self.authenticated_hosts.pop(ip, None)

        if token and token in self.tokens:
            self.tokens[token]["bound_ip"] = None

        self.install_drop_rule_for_ip(ip)
        self.remove_return_flows_for_ip(ip)

        return True

    def is_host_authenticated_or_allowed(self, ip):
        if ip in self.blocked_ips:
            return False

        if ip in self.manual_allowed_ips:
            return True

        if ip in self.authenticated_hosts:
            return True

        return False

    def remember_icmp_return_flow(self, src_ip, dst_ip):
        # Authenticated src_ip sent an ICMP echo-request to dst_ip.
        # Therefore, dst_ip may send echo-reply back to src_ip.
        self.allowed_icmp_return_flows.add((dst_ip, src_ip))

    def is_icmp_return_allowed(self, src_ip, dst_ip):
        return (src_ip, dst_ip) in self.allowed_icmp_return_flows

    def remove_return_flows_for_ip(self, ip):
        self.allowed_icmp_return_flows = {
            flow for flow in self.allowed_icmp_return_flows
            if ip not in flow
        }

    # OpenFlow event handlers
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )
        ]

        self.add_flow(
            datapath=datapath,
            priority=0,
            match=parser.OFPMatch(),
            actions=actions,
        )

        self.logger.info("Switch connected. Datapath ID: %s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        start_time = time.time()

        msg = ev.msg
        datapath = msg.datapath
        self.datapaths[datapath.id] = datapath

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        src_mac = eth.src
        dst_mac = eth.dst
        self.mac_to_port[dpid][src_mac] = in_port

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        icmp_pkt = pkt.get_protocol(icmp.icmp)

        # ARP handling
        # ARP is allowed so hosts can resolve MAC addresses.
        # No generic flow is installed for ARP.
        if arp_pkt:
            self.logger.info("ARP packet allowed: %s -> %s", src_mac, dst_mac)
            self.forward_packet(datapath, msg, in_port, dst_mac, dpid)
            return

        # IPv4 handling
        if eth.ethertype == ether_types.ETH_TYPE_IP and ip_pkt is None:
            self.logger.warning("Dropping malformed/unparsed IPv4 packet")
            return

        if ip_pkt is None:
            self.logger.warning("Dropping non-IPv4/non-ARP packet")
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        src_is_authenticated = self.is_host_authenticated_or_allowed(src_ip)

        is_icmp_echo_request = (
                icmp_pkt is not None and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST
        )

        is_icmp_echo_reply = (
                icmp_pkt is not None and icmp_pkt.type == icmp.ICMP_ECHO_REPLY
        )

        is_allowed_icmp_return = (
                is_icmp_echo_reply and self.is_icmp_return_allowed(src_ip, dst_ip)
        )

        self.logger.info(
            "IPv4 packet: %s -> %s, auth=%s, icmp_type=%s",
            src_ip,
            dst_ip,
            src_is_authenticated,
            icmp_pkt.type if icmp_pkt else None,
        )

        # Authenticated hosts may initiate traffic.
        if src_is_authenticated:
            if is_icmp_echo_request:
                self.remember_icmp_return_flow(src_ip, dst_ip)

            self.logger.info("ALLOWED authenticated traffic: %s -> %s", src_ip, dst_ip)
            self.forward_packet(datapath, msg, in_port, dst_mac, dpid, ip_pkt, icmp_pkt)
            self.log_decision_time(start_time)
            return

        # Unauthenticated hosts may only send ICMP echo-reply return traffic.
        if is_allowed_icmp_return:
            self.logger.info("ALLOWED ICMP return traffic: %s -> %s", src_ip, dst_ip)
            self.forward_packet(datapath, msg, in_port, dst_mac, dpid, ip_pkt, icmp_pkt)
            self.log_decision_time(start_time)
            return

        # Everything else from unauthenticated hosts is blocked.
        self.logger.warning(
            "BLOCKED unauthenticated initiated traffic: %s -> %s",
            src_ip,
            dst_ip,
        )
        self.log_decision_time(start_time)
        return

    def forward_packet(self, datapath, msg, in_port, dst_mac, dpid, ip_pkt=None, icmp_pkt=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        # Install only strict IPv4 allow rules.
        # No generic L2 rules are installed.
        if ip_pkt is not None and out_port != ofproto.OFPP_FLOOD:
            match_kwargs = {
                "eth_type": ether_types.ETH_TYPE_IP,
                "ipv4_src": ip_pkt.src,
                "ipv4_dst": ip_pkt.dst,
            }

            if icmp_pkt is not None:
                match_kwargs["ip_proto"] = 1
                match_kwargs["icmpv4_type"] = icmp_pkt.type

            match = parser.OFPMatch(**match_kwargs)

            self.add_flow(
                datapath=datapath,
                priority=50,
                match=match,
                actions=actions,
                idle_timeout=5,
                hard_timeout=0,
            )

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )

        datapath.send_msg(out)

    def log_decision_time(self, start_time):
        delay_ms = (time.time() - start_time) * 1000
        self.logger.info("Controller decision time: %.3f ms", delay_ms)


class IoTRESTController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(IoTRESTController, self).__init__(req, link, data, **config)
        self.iot_app = data[iot_instance_name]

    def json_response(self, data, status=200):
        return Response(
            content_type="application/json",
            charset="utf-8",
            status=status,
            body=json.dumps(data, indent=2).encode("utf-8"),
        )

    def parse_body(self, req):
        try:
            return json.loads(req.body.decode("utf-8"))
        except Exception:
            return {}

    @route("iot", "/state", methods=["GET"])
    def get_state(self, req, **kwargs):
        app = self.iot_app

        return self.json_response({
            "blocked_ips": sorted(list(app.blocked_ips)),
            "manual_allowed_ips": sorted(list(app.manual_allowed_ips)),
            "authenticated_hosts": app.authenticated_hosts,
            "tokens": app.tokens,
            "allowed_icmp_return_flows": sorted([
                f"{src}->{dst}" for src, dst in app.allowed_icmp_return_flows
            ]),
        })

    @route("iot", "/flows/clear", methods=["POST"])
    def clear_flows(self, req, **kwargs):
        app = self.iot_app
        app.clear_all_flows_and_reinstall_table_miss()

        return self.json_response({
            "message": "all flows cleared and table-miss rule reinstalled",
        })

    @route("iot", "/state/clear", methods=["POST"])
    def clear_state(self, req, **kwargs):
        app = self.iot_app

        app.blocked_ips.clear()
        app.manual_allowed_ips.clear()
        app.tokens.clear()
        app.authenticated_hosts.clear()
        app.allowed_icmp_return_flows.clear()
        app.mac_to_port.clear()
        app.clear_all_flows_and_reinstall_table_miss()

        return self.json_response({
            "message": "controller state and flows cleared",
        })

    # ACL endpoints
    @route("iot", "/acl", methods=["GET"])
    def get_acl(self, req, **kwargs):
        app = self.iot_app

        return self.json_response({
            "blocked_ips": sorted(list(app.blocked_ips)),
            "manual_allowed_ips": sorted(list(app.manual_allowed_ips)),
        })

    @route("iot", "/acl/block", methods=["POST"])
    def acl_block(self, req, **kwargs):
        app = self.iot_app
        body = self.parse_body(req)

        ip = body.get("ip")

        if not ip:
            return self.json_response({"error": "missing ip"}, status=400)

        app.blocked_ips.add(ip)
        app.manual_allowed_ips.discard(ip)
        app.authenticated_hosts.pop(ip, None)

        for _, record in app.tokens.items():
            if record["bound_ip"] == ip:
                record["bound_ip"] = None

        app.remove_return_flows_for_ip(ip)
        app.install_drop_rule_for_ip(ip)

        return self.json_response({
            "message": "host blocked",
            "ip": ip,
        })

    @route("iot", "/acl/allow", methods=["POST"])
    def acl_allow(self, req, **kwargs):
        app = self.iot_app
        body = self.parse_body(req)

        ip = body.get("ip")

        if not ip:
            return self.json_response({"error": "missing ip"}, status=400)

        app.blocked_ips.discard(ip)
        app.manual_allowed_ips.add(ip)
        app.remove_drop_rules_for_ip(ip)

        return self.json_response({
            "message": "host manually allowed",
            "ip": ip,
        })

    # Token endpoints
    @route("iot", "/token", methods=["GET"])
    def list_tokens(self, req, **kwargs):
        return self.json_response({
            "tokens": self.iot_app.tokens,
        })

    @route("iot", "/token/create", methods=["POST"])
    def token_create(self, req, **kwargs):
        token = self.iot_app.create_token()

        return self.json_response({
            "message": "token created",
            "token": token,
        })

    @route("iot", "/token/revoke", methods=["POST"])
    def token_revoke(self, req, **kwargs):
        app = self.iot_app
        body = self.parse_body(req)

        token = body.get("token")

        if not token:
            return self.json_response({"error": "missing token"}, status=400)

        ok, message = app.revoke_token(token)

        if not ok:
            return self.json_response({"error": message}, status=404)

        return self.json_response({
            "message": message,
            "token": token,
        })

    # Authentication endpoints
    @route("iot", "/auth/login", methods=["POST"])
    def auth_login(self, req, **kwargs):
        app = self.iot_app
        body = self.parse_body(req)

        ip = body.get("ip")
        token = body.get("token")

        if not ip:
            return self.json_response({"error": "missing ip"}, status=400)

        if not token:
            return self.json_response({"error": "missing token"}, status=400)

        ok, message = app.authenticate_host(ip, token)

        return self.json_response({
            "authenticated": ok,
            "message": message,
            "ip": ip,
        }, status=200 if ok else 403)

    @route("iot", "/auth/logout", methods=["POST"])
    def auth_logout(self, req, **kwargs):
        app = self.iot_app
        body = self.parse_body(req)

        ip = body.get("ip")

        if not ip:
            return self.json_response({"error": "missing ip"}, status=400)

        app.logout_host(ip)

        return self.json_response({
            "message": "host logged out and blocked",
            "ip": ip,
        })