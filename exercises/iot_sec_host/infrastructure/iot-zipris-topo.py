from mininet.topo import Topo


class ZiprisTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        # Add hosts
        h1 = self.addHost('h1')  # SmartNIC
        h2 = self.addHost('h2')  # IoT Device #1
        h3 = self.addHost('h3')  # Non-IoT Device
        h4 = self.addHost('h4')  # IoT Device #2
        h5 = self.addHost('h5')  # Valid Destination #1
        h6 = self.addHost('h6')  # Invalid Destination #1
        h7 = self.addHost('h7')  # Valid Destination #2
        h8 = self.addHost('h8')  # Invalid Destination #2
        # Add switches
        s1 = self.addSwitch('s1')  # Home Switch #1
        s2 = self.addSwitch('s2')  # Home Switch #2
        s3 = self.addSwitch('s3')  # Destination Switch #1
        s4 = self.addSwitch('s4')  # Destination Switch #2
        r1 = self.addSwitch('r1')  # Router
        # Add links
        self.addLink(h2, s1)
        self.addLink(h3, s1)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)
        self.addLink(h7, s4)
        self.addLink(h8, s4)
        self.addLink(h1, r1)
        self.addLink(s1, r1)
        self.addLink(s2, r1)
        self.addLink(s3, r1)
        self.addLink(s4, r1)


topos = {'ziprisTopo': (lambda: ZiprisTopo())}
