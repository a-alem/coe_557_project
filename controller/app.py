import time

from ryu.base import app_manager
from ryu.app.wsgi import WSGIApplication
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import arp, ethernet, ether_types, icmp, ipv4, packet
from ryu.ofproto import ofproto_v1_3

from .constants import APP_INSTANCE_NAME
from .openflow import OpenFlowManager
from .policy import AccessPolicyService
from .rest import IoTRESTController


class IoTACLTokenController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(IoTACLTokenController, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}

        self.flow_manager = OpenFlowManager(logger=self.logger)
        self.policy = AccessPolicyService(
            drop_installer=lambda ip: self.flow_manager.install_drop_rule_for_ip(
                self.datapaths, ip
            ),
            drop_remover=lambda ip: self.flow_manager.remove_drop_rules_for_ip(
                self.datapaths, ip
            ),
        )

        wsgi = kwargs["wsgi"]
        wsgi.register(IoTRESTController, {APP_INSTANCE_NAME: self})

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

        self.flow_manager.add_flow(
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

        if arp_pkt:
            self.logger.info("ARP packet allowed: %s -> %s", src_mac, dst_mac)
            self.forward_packet(datapath, msg, in_port, dst_mac, dpid)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP and ip_pkt is None:
            self.logger.warning("Dropping malformed/unparsed IPv4 packet")
            return

        if ip_pkt is None:
            self.logger.warning("Dropping non-IPv4/non-ARP packet")
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        src_is_authenticated = self.policy.is_host_authenticated_or_allowed(src_ip)

        is_icmp_echo_request = (
            icmp_pkt is not None and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST
        )
        is_icmp_echo_reply = (
            icmp_pkt is not None and icmp_pkt.type == icmp.ICMP_ECHO_REPLY
        )

        is_allowed_icmp_return = (
            is_icmp_echo_reply and self.policy.is_icmp_return_allowed(src_ip, dst_ip)
        )

        self.logger.info(
            "IPv4 packet: %s -> %s, auth=%s, icmp_type=%s",
            src_ip,
            dst_ip,
            src_is_authenticated,
            icmp_pkt.type if icmp_pkt else None,
        )

        if src_is_authenticated:
            if is_icmp_echo_request:
                self.policy.remember_icmp_return_flow(src_ip, dst_ip)

            self.logger.info("ALLOWED authenticated traffic: %s -> %s", src_ip, dst_ip)
            self.forward_packet(datapath, msg, in_port, dst_mac, dpid, ip_pkt, icmp_pkt)
            self.log_decision_time(start_time)
            return

        if is_allowed_icmp_return:
            self.logger.info("ALLOWED ICMP return traffic: %s -> %s", src_ip, dst_ip)
            self.forward_packet(datapath, msg, in_port, dst_mac, dpid, ip_pkt, icmp_pkt)
            self.log_decision_time(start_time)
            return

        self.logger.warning(
            "BLOCKED unauthenticated initiated traffic: %s -> %s",
            src_ip,
            dst_ip,
        )
        self.log_decision_time(start_time)

    def forward_packet(self, datapath, msg, in_port, dst_mac, dpid, ip_pkt=None, icmp_pkt=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

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

            self.flow_manager.add_flow(
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
