import time

from ryu.base import app_manager
from ryu.app.wsgi import WSGIApplication
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.ofproto import ofproto_v1_3

from .constants import APP_INSTANCE_NAME, CLOUD_SERVER_IP
from .openflow import OpenFlowManager
from .policy import AccessPolicyService
from .rest import IoTRESTController


class IoTACLTokenController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

    CLOUD_SERVER_IP = CLOUD_SERVER_IP

    def __init__(self, *args, **kwargs):
        super(IoTACLTokenController, self).__init__(*args, **kwargs)

        self.mac_to_port = {}
        self.datapaths = {}

        self.flow_manager = OpenFlowManager(
            cloud_server_ip=self.CLOUD_SERVER_IP,
            logger=self.logger,
        )
        self.policy = AccessPolicyService(
            drop_installer=lambda ip: self.flow_manager.install_drop_rule(self.datapaths, ip),
            drop_remover=lambda ip: self.flow_manager.remove_drop_rule(self.datapaths, ip),
        )

        wsgi = kwargs["wsgi"]
        wsgi.register(IoTRESTController, {APP_INSTANCE_NAME: self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]

        self.flow_manager.add_flow(datapath, priority=0, match=match, actions=actions)
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
                if not self.policy.is_host_allowed(src_ip):
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

                    self.flow_manager.add_flow(
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
            self.flow_manager.add_flow(
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
