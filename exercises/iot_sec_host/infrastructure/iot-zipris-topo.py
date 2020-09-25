from mininet.topo import Topo


class ZiprisTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        # Add hosts
        h1 = self.addHost('h1')  # SmartNIC
        h2 = self.addHost('h2')  # IoT Device #1
        h4 = self.addHost('h4')  # Non-IoT Device
        h5 = self.addHost('h5')  # Valid Destination #1
        h6 = self.addHost('h6')  # Invalid Destination #1
        h7 = self.addHost('h7')  # IoT Device #2
        h8 = self.addHost('h8')  # Valid Destination #2
        h9 = self.addHost('h9')  # Invalid Destination #2
        # Add switches
        s2 = self.addSwitch('s2')  # Home Switch #1
        s3 = self.addSwitch('s3')  # Destination Switch #1
        s4 = self.addSwitch('s4')  # Home Switch #2
        s5 = self.addSwitch('s5')  # Destination Switch #2
        r1 = self.addSwitch('r1')  # Router
        # Add links
        self.addLink(h2, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)
        self.addLink(h7, s4)
        self.addLink(h8, s5)
        self.addLink(h9, s5)
        self.addLink(h1, r1)
        self.addLink(s2, r1)
        self.addLink(s3, r1)
        self.addLink(s4, r1)
        self.addLink(s5, r1)


topos = {'ziprisTopo': (lambda: ZiprisTopo())}