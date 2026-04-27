from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4


class IoTACLController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Authorized IoT devices allowed to reach the cloud server
    ALLOWED_IOT_IPS = {
        "10.0.0.1",  # h1
        "10.0.0.2",  # h2
    }

    CLOUD_SERVER_IP = "10.0.0.4"  # h4

    def __init__(self, *args, **kwargs):
        super(IoTACLController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss rule: send unknown packets to controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                   ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

        self.logger.info("Switch connected. Table-miss flow installed.")

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

    def drop_flow(self, datapath, match):
        # Empty actions = drop
        self.add_flow(datapath, priority=100, match=match, actions=[], idle_timeout=30)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

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

            # ACL rule:
            # If a device tries to reach the cloud server and is not authorized, block it.
            if dst_ip == self.CLOUD_SERVER_IP and src_ip not in self.ALLOWED_IOT_IPS:
                self.logger.warning(
                    "BLOCKED unauthorized IoT device: %s -> %s",
                    src_ip,
                    dst_ip,
                )

                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                )
                self.drop_flow(datapath, match)
                return

            if dst_ip == self.CLOUD_SERVER_IP:
                self.logger.info(
                    "ALLOWED authorized IoT device: %s -> %s",
                    src_ip,
                    dst_ip,
                )

        # Normal L2 learning-switch forwarding
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
            self.add_flow(datapath, priority=1, match=match, actions=actions, idle_timeout=30)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)