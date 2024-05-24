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
DEFAULT_IDLE_TIMEOUT = 30 # Soglia predefinita per l'inattività di una connessione in secondi
PACKET_THRESHOLD = 0
IDLE_TIMEOUT = 0

# Caricamento delle configurazioni
with open('config.txt', 'r') as file:
    packet_threshold_found = False
    idle_timeout_found = False
    for line in file:
        packet_threshold_match = re.search(r'PACKET_THRESHOLD\s*=\s*(\d+)', line)
        idle_timeout_found = re.search(r'IDLE_TIMEOUT\s*=\s*(\d+)', line)
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

# Struttura dati per contenere le connessioni
elephants = {}

class ElephantManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    topo = None
    switch_list = []


    def find_destination_switch(self, mac_destination):
        for host in get_all_host(self):
            if host.mac == mac_destination:
                return (host.port.dpid, host.port.port_no)
        return (None, None)

    def find_next_host_destination(self, source_id, destination_id):
        self.topo = nx.DiGraph()

        for link in get_all_link(self):
            self.topo.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        path = nx.shortest_path(self.topo, source_id, destination_id)

        link_next_hop = self.topo[path[0]][path[1]]
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
                    instructions=inst,
                    idle_timeout=IDLE_TIMEOUT
                )
                datapath.send_msg(mod)

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def _topology_change_handler(self, ev):
        # Aggiorna la topologia
        self.update_topology()
        # Ricalcola i percorsi per tutte le connessioni elefanti attive
        for key, value in elephants.items():
            packet_count, route, isElephant, statsReq = value
            if isElephant:
                # Trova un nuovo percorso
                new_route = self.find_new_route(key[0], key[1])
                if new_route:
                    # Aggiorna il percorso dell'elefante
                    route_tmp = self.build_datapath_route_list(new_route)
                    print(f'NEW ROUTE: ', new_route)
                    print(f'NEW ROUTE: ', new_route)
                    print(f'ROUTE TMP: ', route_tmp)
                    print(f'ROUTE TMP: ', route_tmp)
                    elephants[key] = (packet_count, route_tmp, isElephant, statsReq) #elephants[key] = (packet_count, new_route, isElephant, statsReq)
                    # Aggiorna le regole di instradamento
                    self.update_flow_rules(key[0], key[1], new_route)

    def update_topology(self):
        # Inizializza una nuova rappresentazione della topologia come un grafo diretto
        self.topo = nx.DiGraph()

        # Ottieni tutti gli switch e i link attualmente presenti nella rete
        switches = get_all_switch(self)
        links = get_all_link(self)

        # Aggiungi gli switch come nodi nel grafo
        for switch in switches:
            self.topo.add_node(switch.dp.id)

        # Aggiungi i link come archi nel grafo
        for link in links:
            self.topo.add_edge(link.src.dpid, link.dst.dpid, port=link.src.port_no)

        # Ora la topologia è aggiornata con le informazioni correnti
        print("Topologia aggiornata con successo.")


    def find_new_route(self, mac_src, mac_dst):
        # Assicurati che la topologia sia aggiornata
        self.update_topology()

        # Trova lo switch di partenza e di arrivo per i MAC forniti
        src_dpid, _ = self.find_destination_switch(mac_src)
        dst_dpid, _ = self.find_destination_switch(mac_dst)

        # Se entrambi gli switch sono presenti nella topologia, cerca un nuovo percorso
        if src_dpid and dst_dpid:
            try:
                # Usa NetworkX per trovare il percorso più breve
                path = nx.shortest_path(self.topo, src_dpid, dst_dpid)
                return path
            except nx.NetworkXNoPath:
                print("Nessun percorso trovato.")
                return None
        else:
            print("Uno degli switch non è presente nella topologia.")
            return None

    def update_flow_rules(self, mac_src, mac_dst, route):
        # Per ogni switch nel percorso, aggiorna le regole di flusso
        for i in range(len(route) - 1):
            switch = route[i]
            next_switch = route[i + 1]
            out_port = self.topo[switch][next_switch]['port']

            datapath = self.get_datapath(switch)
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Crea una regola di flusso per inoltrare i pacchetti al prossimo switch
            match = parser.OFPMatch(eth_src=mac_src, eth_dst=mac_dst)
            actions = [parser.OFPActionOutput(out_port)]

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

            mod = parser.OFPFlowMod(datapath=datapath, priority=10, match=match, instructions=inst)
            datapath.send_msg(mod)

    def get_datapath(self, dpid):
        # Cerca tra tutti gli switch conosciuti per trovare quello con il dpid corrispondente
        for switch in self.switch_list:
            if switch.id == dpid:
                return switch
        # Se non viene trovato nessuno switch con il dpid fornito, restituisci None
        return None

    def build_datapath_route_list(self, new_route):
        tmp = []
        for i in range(len(new_route)):
            switch = new_route[i]
            if switch is None:
                break
            tmp.append(self.get_datapath(switch))
        return tmp

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.switch_list.append(datapath)
        # Assicurati di non aggiungere duplicati
        self.switch_list = list(set(self.switch_list))
        print(f"Switch {dpid} aggiunto alla lista degli switch.")
