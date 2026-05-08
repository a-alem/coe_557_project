import json
import time
import uuid

from webob import Response

from ryu.base import app_manager
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.ofproto import ofproto_v1_3


iot_instance_name = "iot_acl_token_app"


class IoTACLTokenController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

    CLOUD_SERVER_IP = "10.0.0.4"

    def __init__(self, *args, **kwargs):
        super(IoTACLTokenController, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}

        # Runtime ACL lists
        self.blocked_ips = set()
        self.manual_allowed_ips = set()

        # Dynamic token store
        # token: {"active": bool, "bound_ip": None or "10.0.0.x"}
        self.tokens = {}

        # Authenticated hosts
        # ip: token
        self.authenticated_hosts = {}

        wsgi = kwargs["wsgi"]
        wsgi.register(IoTRESTController, {iot_instance_name: self})

    # OpenFlow helpers
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match,
        )
        datapath.send_msg(mod)

    def install_drop_rule(self, ip):
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip,
                ipv4_dst=self.CLOUD_SERVER_IP,
            )

            self.add_flow(
                datapath=datapath,
                priority=100,
                match=match,
                actions=[],
                idle_timeout=0,
                hard_timeout=0,
            )

            self.logger.warning("Installed DROP rule: %s -> %s", ip, self.CLOUD_SERVER_IP)

    def remove_drop_rule(self, ip):
        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip,
                ipv4_dst=self.CLOUD_SERVER_IP,
            )

            self.delete_flow(datapath, match)
            self.logger.info("Removed DROP rule if present: %s -> %s", ip, self.CLOUD_SERVER_IP)


    # Token/auth logic
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
            self.install_drop_rule(bound_ip)

        del self.tokens[token]
        return True, "token revoked"

    def authenticate_host(self, ip, token):
        if token not in self.tokens:
            self.install_drop_rule(ip)
            return False, "invalid token"

        token_record = self.tokens[token]

        if not token_record["active"]:
            self.install_drop_rule(ip)
            return False, "token is inactive"

        bound_ip = token_record["bound_ip"]

        # Token is unused, so bind it to this host
        if bound_ip is None:
            token_record["bound_ip"] = ip
            self.authenticated_hosts[ip] = token
            self.blocked_ips.discard(ip)
            self.remove_drop_rule(ip)
            return True, "host authenticated and token bound"

        # Token is already bound to the same host
        if bound_ip == ip:
            self.authenticated_hosts[ip] = token
            self.blocked_ips.discard(ip)
            self.remove_drop_rule(ip)
            return True, "host already authenticated"

        # Token is already used by another host
        self.install_drop_rule(ip)
        return False, "token already bound to another host"

    def logout_host(self, ip):
        token = self.authenticated_hosts.pop(ip, None)

        if token and token in self.tokens:
            self.tokens[token]["bound_ip"] = None

        self.install_drop_rule(ip)
        return True

    def is_host_allowed(self, ip):
        if ip in self.blocked_ips:
            return False

        if ip in self.manual_allowed_ips:
            return True

        if ip in self.authenticated_hosts:
            return True

        return False

    # OpenFlow event handlers
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss rule: send unknown traffic to controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]

        self.add_flow(datapath, priority=0, match=match, actions=actions)

        self.logger.info("Switch connected. Datapath ID: %s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        start_time = time.time()

        msg = ev.msg
        datapath = msg.datapath
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
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

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            if dst_ip == self.CLOUD_SERVER_IP:
                if not self.is_host_allowed(src_ip):
                    self.logger.warning(
                        "BLOCKED unauthenticated/unauthorized host: %s -> %s",
                        src_ip,
                        dst_ip,
                    )

                    match = parser.OFPMatch(
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=src_ip,
                        ipv4_dst=dst_ip,
                    )

                    self.add_flow(
                        datapath=datapath,
                        priority=100,
                        match=match,
                        actions=[],
                        idle_timeout=0,
                        hard_timeout=0,
                    )

                    delay_ms = (time.time() - start_time) * 1000
                    self.logger.info("Controller decision time: %.3f ms", delay_ms)
                    return

                self.logger.info("ALLOWED host: %s -> %s", src_ip, dst_ip)

        # Normal learning-switch forwarding
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst_mac,
                eth_src=src_mac,
            )
            self.add_flow(
                datapath=datapath,
                priority=1,
                match=match,
                actions=actions,
                idle_timeout=30,
            )

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)

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

    # State
    @route("iot", "/state", methods=["GET"])
    def get_state(self, req, **kwargs):
        app = self.iot_app

        return self.json_response({
            "cloud_server_ip": app.CLOUD_SERVER_IP,
            "blocked_ips": sorted(list(app.blocked_ips)),
            "manual_allowed_ips": sorted(list(app.manual_allowed_ips)),
            "authenticated_hosts": app.authenticated_hosts,
            "tokens": app.tokens,
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

        for token, record in app.tokens.items():
            if record["bound_ip"] == ip:
                record["bound_ip"] = None

        app.install_drop_rule(ip)

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
        app.remove_drop_rule(ip)

        return self.json_response({
            "message": "host manually allowed",
            "ip": ip,
        })

    # Token endpoints
    @route("iot", "/token", methods=["GET"])
    def list_tokens(self, req, **kwargs):
        app = self.iot_app

        return self.json_response({
            "tokens": app.tokens,
        })

    @route("iot", "/token/create", methods=["POST"])
    def token_create(self, req, **kwargs):
        app = self.iot_app
        token = app.create_token()

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

        status = 200 if ok else 403

        return self.json_response({
            "authenticated": ok,
            "message": message,
            "ip": ip,
        }, status=status)

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