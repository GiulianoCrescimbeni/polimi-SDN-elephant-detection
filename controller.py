from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, arp
import networkx as nx
import re
import time
import threading

DEFAULT_PACKET_THRESHOLD = 2000  # Default threshold for number of packets of an elephant
DEFAULT_IDLE_TIMEOUT = 30 # Default timeout for connection inactivity in seconds
PACKET_THRESHOLD = 0
IDLE_TIMEOUT = 0

# Loading configurations
with open('config.txt', 'r') as file:
    packet_threshold_found = False
    idle_timeout_found = False
    for line in file:
        packet_threshold_match = re.search(r'PACKET_THRESHOLD\s*=\s*(\d+)', line)
        idle_timeout_match = re.search(r'IDLE_TIMEOUT\s*=\s*(\d+)', line)
        if packet_threshold_match:
            PACKET_THRESHOLD = int(packet_threshold_match.group(1))
            packet_threshold_found = True
        if idle_timeout_found:
            IDLE_TIMEOUT = int(idle_timeout_match.group(1))
            idle_timeout_found = True

    if packet_threshold_found:
        print("Packet threshold:", PACKET_THRESHOLD)
    else:
        PACKET_THRESHOLD = DEFAULT_PACKET_THRESHOLD
        print("Using default packet threshold:", PACKET_THRESHOLD)

    if idle_timeout_found:
        print("Idle timeout:", IDLE_TIMEOUT)
    else:
        IDLE_TIMEOUT = DEFAULT_IDLE_TIMEOUT
        print("Using default idle timeout:", IDLE_TIMEOUT)

# Data structure to hold connections
elephants = {}

class ElephantManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    topo = None
    switch_list = []

    # Method to find destination switch based on MAC address
    def find_destination_switch(self, mac_destination):
        for host in get_all_host(self):
            if host.mac == mac_destination:
                return (host.port.dpid, host.port.port_no)
        return (None, None)

    # Method to find next switch port based on source and destination switches
    def find_next_host_destination(self, source_id, destination_id):
        self.topo = nx.DiGraph()

        for link in get_all_link(self):
            self.topo.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        path = nx.shortest_path(self.topo, source_id, destination_id)

        link_next_hop = self.topo[path[0]][path[1]]
        return link_next_hop['port']

    # Event handler for switch features configuration
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _config_dispatcher_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [actions]
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=0,
            match = match,
            instructions=inst
        )
        datapath.send_msg(mod)

    # Event handler for packet in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        input_port = ev.msg.match['in_port']

        # Parsing
        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_in = pkt.get_protocol(arp.arp)

        if arp_in:
            assert arp_in.opcode == arp.ARP_REQUEST
            destination_host_mac = None

            host_list = get_all_host(self)
            for host in host_list:
                if arp_in.dst_ip in host.ipv4:
                    destination_host_mac = host.mac
                    break

            # Host not found
            if destination_host_mac is None:
                return

            pkt_out = packet.Packet()
            eth_out = ethernet.ethernet(
                dst = eth.src,
                src = destination_host_mac,
                ethertype = ether_types.ETH_TYPE_ARP
            )
            arp_out = arp.arp(
                opcode  = arp.ARP_REPLY,
                src_mac = destination_host_mac,
                src_ip  = arp_in.dst_ip,
                dst_mac = arp_in.src_mac,
                dst_ip  = arp_in.src_ip
            )
            pkt_out.add_protocol(eth_out)
            pkt_out.add_protocol(arp_out)
            pkt_out.serialize()

            actions = [
                parser.OFPActionOutput(
                    input_port
                )
            ]

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=pkt_out.data
            )
            datapath.send_msg(out)

        else:

            # Check if the packet is IPV4
            if eth.ethertype != ether_types.ETH_TYPE_IP:
                return

            mac_dst = eth.dst
            mac_src = eth.src

            # Find destination switch
            dpid, port_no = self.find_destination_switch(mac_dst)

            if dpid is None or port_no is None:
                return

            # Find shortest path to destination switch
            if datapath.id == dpid:
                output_port = port_no
            else:
                output_port = self.find_next_host_destination(datapath.id, dpid)

            # Forward packet to destination
            actions = [parser.OFPActionOutput(output_port)]

            out = parser.OFPPacketOut(
                datapath = datapath,
                buffer_id = ev.msg.buffer_id,
                in_port = input_port,
                actions = actions,
                data = ev.msg.data
            )

            datapath.send_msg(out)

            dpid, port_no = self.find_destination_switch(mac_src)

            if dpid is None or port_no is None:
                return

            # Check if tcp
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if not tcp_pkt:
                return

            # Verify source host is directly connected to the switch
            if datapath.id == dpid:
                # Update packet count only if source MAC is connected to the switch
                if (mac_src, mac_dst) not in elephants:
                    elephants[(mac_src, mac_dst)] = (1, [datapath], False, False)
                    packet_count, route, isElephant, statsReq = elephants[(mac_src, mac_dst)]

                else:
                    packet_count, route, isElephant, statsReq = elephants[(mac_src, mac_dst)]
                    elephants[(mac_src, mac_dst)] = (packet_count + 1, route, False, False)

            packet_count, route, isElephant, statsReq = elephants[(mac_src, mac_dst)]
            if datapath not in route:
                    route.append(datapath)
                    elephants[(mac_src, mac_dst)] = (packet_count, route, isElephant, statsReq)

            print("Number of packets -> ", packet_count)
            print("Route -> ", elephants[(mac_src, mac_dst)][1])

            if elephants[(mac_src, mac_dst)][0] >= PACKET_THRESHOLD:
                elephants[(mac_src, mac_dst)] = (packet_count, route, True, False)
                print(f"Elephant identified from {mac_src} to {mac_dst}")
                # Rule for direct routing of packets
                datapath = ev.msg.datapath
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser

                match = parser.OFPMatch(eth_src = mac_src, eth_dst = mac_dst)
                actions = parser.OFPActionOutput(output_port)

                inst = [
                    parser.OFPInstructionActions(
                        ofproto.OFPIT_APPLY_ACTIONS,
                        [actions]
                    )
                ]

                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    priority=10,
                    match = match,
                    instructions=inst,
                    idle_timeout=IDLE_TIMEOUT
                )
                datapath.send_msg(mod)

    # Handler for topology changes
    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        # Update the topology
        self.update_topology()
        # Recalculate routes for all active elephant connections
        for key, value in elephants.items():
            packet_count, route, isElephant, statsReq = value
            if isElephant:
                # Find a new path
                new_route = self.find_new_route(key[0], key[1])
                if new_route:
                    # Update the path
                    route_tmp = self.build_datapath_route_list(new_route)
                    print(f'NEW ROUTE: ', new_route)
                    print(f'ROUTE TMP: ', route_tmp)
                    elephants[key] = (packet_count, route_tmp, isElephant, statsReq)
                    # Update routing rules
                    self.update_flow_rules(key[0], key[1], new_route)

    # Function to update the topology
    def update_topology(self):
        self.topo = nx.DiGraph()

        switches = get_all_switch(self)
        links = get_all_link(self)

        for switch in switches:
            self.topo.add_node(switch.dp.id)

        for link in links:
            self.topo.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        print("Topology updated successfully.")


    # Function to find a new route from mac_src to mac_dst
    def find_new_route(self, mac_src, mac_dst):
        self.update_topology()

        src_dpid, _ = self.find_destination_switch(mac_src)
        dst_dpid, _ = self.find_destination_switch(mac_dst)

        if src_dpid and dst_dpid:
            try:
                path = nx.shortest_path(self.topo, src_dpid, dst_dpid)
                return path
            except nx.NetworkXNoPath:
                print("No path found.")
                return None
        else:
            print("One of the switches is missing from the topology.")
            return None

    # Function to update flow rules
    def update_flow_rules(self, mac_src, mac_dst, route):
        for i in range(len(route) - 1):
            switch = route[i]
            next_switch = route[i + 1]
            out_port = self.topo[switch][next_switch]['port']

            datapath = self.get_datapath(switch)
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(eth_src=mac_src, eth_dst=mac_dst)
            actions = [parser.OFPActionOutput(out_port)]

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

            mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match, instructions=inst, idle_timeout=IDLE_TIMEOUT)
            datapath.send_msg(mod)

    def get_datapath(self, dpid):
        for switch in self.switch_list:
            if switch.id == dpid:
                return switch
        return None

    def build_datapath_route_list(self, new_route):
        tmp = []
        for i in range(len(new_route)):
            switch = new_route[i]
            if switch is None:
                break
            tmp.append(self.get_datapath(switch))
        return tmp

    # Config Dispatcher event for switch configuration
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.switch_list.append(datapath)
        self.switch_list = list(set(self.switch_list))
        print(f"Switch {dpid} added to the switch list.")
