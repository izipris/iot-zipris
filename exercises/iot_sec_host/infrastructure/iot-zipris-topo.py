from mininet.topo import Topo


class ZiprisTopo(Topo):
    def __init__(self):
        Topo.__init__(self)
        # Add hosts
        h1 = self.addHost('h1')  # SmartNIC
        h2 = self.addHost('h2')  # IoT Device
        h4 = self.addHost('h4')  # Non-IoT Device
        h5 = self.addHost('h5')  # Valid Destination
        h6 = self.addHost('h6')  # Invalid Destination
        # Add switches
        s2 = self.addSwitch('s2')  # Home Switch
        s3 = self.addSwitch('s3')  # Destination Switch
        r1 = self.addSwitch('r1')  # Router
        # Add links
        self.addLink(h2, s2)
        self.addLink(h4, s2)
        self.addLink(h5, s3)
        self.addLink(h6, s3)
        self.addLink(h1, r1)
        self.addLink(s2, r1)
        self.addLink(s3, r1)


topos = {'ziprisTopo': (lambda: ZiprisTopo())}
