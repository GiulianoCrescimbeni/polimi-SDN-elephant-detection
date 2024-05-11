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

DEFAULT_PACKET_THRESHOLD = 2000  # Soglia predefinita per il numero di pacchetti
DEFAULT_SECONDS_BETWEEN_ANALYSIS = 30 # Soglia predefinita per la frequenza di analisi delle connessioni elefanti
DEFAULT_ELEPHANT_PACKET_THRESHOLD = 1000 # Soglia predefinita per l'inattività di una connessione in n°pacchetti
PACKET_THRESHOLD = 0
SECONDS_BETWEEN_ANALYSIS = 0
ELEPHANT_PACKET_THRESHOLD = 0

# Caricamento delle configurazioni
with open('config.txt', 'r') as file:
    packet_threshold_found = False
    seconds_between_analysis_found = False
    elephant_packet_threshold_found = False
    for line in file:
        packet_threshold_match = re.search(r'PACKET_THRESHOLD\s*=\s*(\d+)', line)
        seconds_between_analysis_match = re.search(r'SECONDS_BETWEEN_ANALYSIS\s*=\s*(\d+)', line)
        elephant_packet_threshold_match = re.search(r'ELEPHANT_PACKET_THRESHOLD\s*=\s*(\d+)', line)
        if packet_threshold_match:
            PACKET_THRESHOLD = int(packet_threshold_match.group(1))
            packet_threshold_found = True
        elif seconds_between_analysis_match:
            SECONDS_BETWEEN_ANALYSIS = int(seconds_between_analysis_match.group(1))
            seconds_between_analysis_found = True
        elif elephant_packet_threshold_match:
            ELEPHANT_PACKET_THRESHOLD = int(elephant_packet_threshold_match.group(1))
            elephant_packet_threshold_found = True

    if packet_threshold_found:
        print("Packet threshold:", PACKET_THRESHOLD)
    else:
        PACKET_THRESHOLD = DEFAULT_PACKET_THRESHOLD
        print("Using default packet threshold:", PACKET_THRESHOLD)
    if seconds_between_analysis_found:
        print("Seconds between analysis:", SECONDS_BETWEEN_ANALYSIS)
    else:
        SECONDS_BETWEEN_ANALYSIS = DEFAULT_SECONDS_BETWEEN_ANALYSIS
        print("Using default seconds between analysis:", SECONDS_BETWEEN_ANALYSIS)
    if elephant_packet_threshold_found:
        print("Elephant packet threshold:", ELEPHANT_PACKET_THRESHOLD)
    else:
        ELEPHANT_PACKET_THRESHOLD = DEFAULT_ELEPHANT_PACKET_THRESHOLD
        print("Using default elephant packet threshold:", ELEPHANT_PACKET_THRESHOLD)

# Struttura dati per contenere le connessioni
elephants = {}

def check_inactive_connections():
        while True:
            for key, value in elephants.items():
                packet_count, route, isElephant, statsReq = value
                current_time = time.time()
                if isElephant == True:
                    datapath = route[0]
                    ofproto = datapath.ofproto
                    parser = datapath.ofproto_parser

                    match = parser.OFPMatch(eth_dst=key[0], eth_src=key[1])
                    req = parser.OFPFlowStatsRequest(datapath, match=match)

                    datapath.send_msg(req)

                    print(req)
                    print("FlowStatsRequest inviato a " + str(datapath.id))

                    elephants[(key[0], key[1])] = (value[0], value[1], value[2], True)

            time.sleep(SECONDS_BETWEEN_ANALYSIS)

# Avvio del thread per verifica di inattività delle connessioni
thread = threading.Thread(target=check_inactive_connections)
thread.daemon = True
thread.start()

class ElephantManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def find_destination_switch(self, mac_destination):
        for host in get_all_host(self):
            if host.mac == mac_destination:
                return (host.port.dpid, host.port.port_no)
        return (None, None)
    
    def find_next_host_destination(self, source_id, destination_id):
        topo = nx.DiGraph()

        for link in get_all_link(self):
            topo.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        path = nx.shortest_path(topo, source_id, destination_id)

        link_next_hop = topo[path[0]][path[1]]
        return link_next_hop['port']

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        input_port = ev.msg.match['in_port']

        #Parsing del pacchetto
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

            # Host non trovato
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

            #Controllare se il pacchetto è IPV4
            if eth.ethertype != ether_types.ETH_TYPE_IP:
                return
            
            mac_dst = eth.dst
            mac_src = eth.src

            #Trovare lo switch destinazione
            dpid, port_no = self.find_destination_switch(mac_dst)

            if dpid is None or port_no is None:
                return

            #Trovare il percorso più breve verso lo switch destinazione
            if datapath.id == dpid:
                output_port = port_no
            else:
                output_port = self.find_next_host_destination(datapath.id, dpid)

            #Inoltrare il pacchetto verso la destinazione
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
            
            #Controllare il protocollo
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if not tcp_pkt:
                return

            #Verifica che l'host sorgente sia direttamente collegato allo switch
            if datapath.id == dpid:
                #Aggiorno il contatore di pacchetti solo se il mac sorgente è collegato allo switch
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
                print(f"Elefante identificato da {mac_src} verso {mac_dst}")
                #Inserire la regola sullo switch per l'instradamento diretto dei pacchetti
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
                    instructions=inst
                )
                datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        # Estrai il messaggio di risposta dalle statistiche di flusso
        msg = ev.msg
        for stat in msg.body:
            match = stat.match
            if 'eth_src' in match:
                mac_src = match['eth_src']
                mac_dst = match['eth_dst']
                packet_count_stat = stat.packet_count
                if elephants.get((mac_src, mac_dst)):
                    packet_count, route, isElephant, statsReq = elephants[(mac_src, mac_dst)]
                    
                    if statsReq:
                        print(f"Switch {ev.msg.datapath.id}: {mac_src} -> {mac_dst} - Packet Count: {packet_count_stat}")

                        packet_count, route, isElephant, statsReq = elephants[(mac_src, mac_dst)]
                        print("Attività in pacchetti: " + str(packet_count_stat - packet_count))
                        if packet_count_stat - packet_count < ELEPHANT_PACKET_THRESHOLD:
                            print(f"Connessione inattiva, rimuovo la connessione: {mac_src} -> {mac_dst}")
                            for switch in route:
                                datapath = switch
                                ofproto = datapath.ofproto 
                                parser = datapath.ofproto_parser
                                match = parser.OFPMatch(eth_src=mac_src, eth_dst=mac_dst)
                                mod = parser.OFPFlowMod(
                                    datapath=datapath,
                                    priority=10,
                                    match=match,
                                    command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY
                                )
                                datapath.send_msg(mod)
                            elephants.pop((mac_src, mac_dst))
                        else:
                            elephants[(mac_src, mac_dst)] = (packet_count_stat, route, True, False)