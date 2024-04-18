"""
 - Nel codice ci sono tanti print che ho messo per capire se stessi facendo la cosa giusta, si possono eliminare tranquillamente.
 - La sezione riguardante la lettura da file è commentata perchè sul mio PC non vuole funzionare per qualche motivo, ma questo probabilmente succede perchè non ho installato correttamente qualcosa ma non ho voglia di correggerlo.
 - Bug da (provare) a risolvere:
    In una topologia lineare con 3 switch e 3 host, se settiamo un server in h1 e il client in h3 il conteggio dei pacchetti avviene regolarmente,
    mentre se dopo aver raggiunto il THRESHOLD invertissimo host e client il conteggio dei pacchetti non è più corretto, salta la conta di alcuni pacchetti
    Possibili soluzioni:
    - Scrivere delle regole diverse per gestire questa casistica
    - Ignorare e sperare che il prof non se ne accorga (possibile perchè in tutti gli altri casi funziona senza problemi)
by Angelo
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls, CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_all_switch, get_all_link, get_all_host
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp
import networkx as nx

DEFAULT_PACKET_THRESHOLD = 20  # Soglia predefinita per il numero di pacchetti
PACKET_THRESHOLD = 0

# Caricamento della soglia di pacchetti dal file di configurazione
#with open('config.txt', 'r') as file:
    #match = re.search(r'PACKET_THRESHOLD\s*=\s*(\d+)', file.read())
    #if match:
        #PACKET_THRESHOLD = int(match.group(1))
        #print("Packet Threshold:", PACKET_THRESHOLD)
    #else:
PACKET_THRESHOLD = DEFAULT_PACKET_THRESHOLD
print("Using Default Packet Threshold:", PACKET_THRESHOLD)

elephants = {}
hop_number_max = 1
latest_dst_mac = None

class ElephantManager(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_fehop_number_maxatures_handler(self, ev):
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

    #Conta numero di hop presenti nel percorso del pacchetto
    def calculate_total_hops(self, source_id, destination_id):
        # Creare un grafo diretto per rappresentare la topologia della rete
        topo = nx.DiGraph()

        # Aggiungere gli archi al grafo in base ai collegamenti tra gli switch
        for link in get_all_link(self):
            topo.add_edge(link.src.dpid, link.dst.dpid)

        path = nx.shortest_path(topo, source_id, destination_id)
        total_hops = len(path)
        return total_hops

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global hop_number_max
        global latest_dst_mac

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        input_port = ev.msg.match['in_port']

        #Parsing del pacchetto
        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        #Controllare se il pacchetto è IPV4
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return
        
        mac_dst = eth.dst

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

        src_mac = eth.src
        dst_mac = eth.dst
        hop_number = self.calculate_total_hops(datapath.id, dpid)
        if(latest_dst_mac!=dst_mac): #Se il pacchetto da trattare è diverso dall'ultimo pacchetto, aggiorna il latest_dst_mac e riporta a 1 hop_number_max
            latest_dst_mac=dst_mac
            hop_number_max=1
        if(hop_number_max<hop_number):
            hop_number_max = hop_number #hop_number_max conterrà il numero di hop che il pacchetto deve attraversare
        print(f"Hop number: {hop_number}\nHop number max: {hop_number_max}")

        # Controllare se il pacchetto è IPV4
        if eth.ethertype != ether_types.ETH_TYPE_IP:
            return
        
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return
        
        #Controllare il protocollo
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if not tcp_pkt:
            return
        # Rilevamento degli elefanti basato sul numero di pacchetti
        print(f"SOURCE: {src_mac}")
        print(f"DESTINATION: {dst_mac}")
        if (src_mac, dst_mac) not in elephants:
            elephants[(src_mac, dst_mac)] = (1/hop_number_max)
        else:
            elephants[(src_mac, dst_mac)] += (1/hop_number_max) #Per evitare che lo stesso pacchetto venga contato più volte
        print(elephants[(src_mac, dst_mac)])
        print(f"Calcolo:{1/hop_number_max}")
        print(f"Nuovo MAX: {hop_number_max}\n")
        print(elephants)
        #if(elephants[(src_mac, dst_mac)] != elephants[(dst_mac, src_mac)]): #Ogni tanto il conteggio dei pacchetti impazzisce
            #tmp = max(elephants[(src_mac, dst_mac)], elephants[(dst_mac, src_mac)])
            #elephants[(src_mac, dst_mac)] = tmp
            #elephants[(dst_mac, src_mac)] = tmp

        if elephants[(src_mac, dst_mac)] >= PACKET_THRESHOLD:
            print(f"Elefante identificato da {src_mac} verso {dst_mac}")
            #Inserire la regola sullo switch
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(eth_dst = dst_mac)

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