from ryu.lib.packet import ether_types


class OpenFlowManager:
    def __init__(self, logger):
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

    def install_drop_rule_for_ip(self, datapaths, ip):
        for datapath in datapaths.values():
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

    def remove_drop_rules_for_ip(self, datapaths, ip):
        for datapath in datapaths.values():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_src=ip,
            )

            self.delete_flow(datapath, match)
            self.logger.info("Removed DROP rule for source IP if present: %s", ip)

    def clear_all_flows_and_reinstall_table_miss(self, datapaths):
        for datapath in datapaths.values():
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=parser.OFPMatch(),
            )
            datapath.send_msg(mod)

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
