from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from ryu.lib.packet import packet, ethernet, ether_types
import networkx as nx

DEFAULT_CONNECTION_THRESHOLD = 5
TCP_CONNECTION_THRESHOLD = 0

with open('config.txt', 'r') as file:
    match = re.search(r'THRESHOLD\s*=\s*(\d+)', file.read())
    if match:
        TCP_CONNECTION_THRESHOLD = int(match.group(1))
        print "Connection Threshold: ", TCP_CONNECTION_THRESHOLD, "s"
    else:
        TCP_CONNECTION_THRESHOLD = DEFAULT_CONNECTION_THRESHOLD
        print "Using Default Connection Threshold: ", TCP_CONNECTION_THRESHOLD, "s"


elephants = []

class ElephantManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_AtCTIONS,
                [
                    parser.OFPActionOutput(
                        ofproto.OFPP_CONTROLLER,
                        ofproto.OFPCML_NO_BUFFER)
                ]
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match = parser.OFPMatch(),
            instructions=inst
        )
        datapath.send_msg(mod)

    def find_destination_switch(self,destination_mac):
        for host in get_all_host(self):
            if host.mac == destination_mac:
                return (host.port.dpid, host.port.port_no)
        return (None,None)

    def find_next_hop_to_destination(self,source_id,destination_id):
        net = nx.DiGraph()
        for link in get_all_link(self):
            net.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        path = nx.shortest_path(
            net,
            source_id,
            destination_id
        )

        first_link = net[ path[0] ][ path[1] ]

        return first_link['port']

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return

        destination_mac = eth.dst

        (dst_dpid, dst_port) = self.find_destination_switch(destination_mac)

        if dst_dpid is None:
            return

        if dst_dpid == datapath.id:
            output_port = dst_port    
        else:
            output_port = self.find_next_hop_to_destination(datapath.id,dst_dpid)

        # print "DP: ", datapath.id, "Host: ", pkt_ip.dst, "Port: ", output_port

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            tcp = pkt.get_protocol(tcp.tcp)
            if tcp:
                src_ip = ip.src
                dst_ip = ip.dst
                src_port = tcp.src_port
                dst_port = tcp.dst_port
                key = (src_ip, dst_ip, src_port, dst_port)

                if key not in self.elephants:
                    self.elephants[key] = (time.time())

                current_time = time.time()

                if current_time - self.elephants[key] >= TCP_CONNECTION_THRESHOLD:
                    match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype,
                                            ipv4_src=src_ip, ipv4_dst=dst_ip,
                                            tcp_src=src_port, tcp_dst=dst_port)
                    actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)] 
                    mod = parser.OFPFlowMod(
                        datapath=datapath,
                        priority=10,
                        match=match,
                        instructions=inst
                    )
                    datapath.send_msg(mod)



        actions = [ parser.OFPActionOutput(output_port) ]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)