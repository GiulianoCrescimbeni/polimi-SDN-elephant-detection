from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

topos = { 'anello': ( lambda: AnelloTopo() ) }

class AnelloTopo(Topo):
    def build(self):
        # Aggiungi gli switch
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        # Aggiungi gli host
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        # Aggiungi i link
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s1)
