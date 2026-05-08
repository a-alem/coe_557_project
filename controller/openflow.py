from ryu.lib.packet import ether_types


class OpenFlowManager:
    def __init__(self, cloud_server_ip, logger):
        self.cloud_server_ip = cloud_server_ip
        self.logger = logger

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

    def install_drop_rule(self, datapaths, ip):
        for datapath in datapaths.values():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip,
                ipv4_dst=self.cloud_server_ip,
            )

            self.add_flow(
                datapath=datapath,
                priority=100,
                match=match,
                actions=[],
                idle_timeout=0,
                hard_timeout=0,
            )

            self.logger.warning("Installed DROP rule: %s -> %s", ip, self.cloud_server_ip)

    def remove_drop_rule(self, datapaths, ip):
        for datapath in datapaths.values():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip,
                ipv4_dst=self.cloud_server_ip,
            )

            self.delete_flow(datapath, match)
            self.logger.info("Removed DROP rule if present: %s -> %s", ip, self.cloud_server_ip)
