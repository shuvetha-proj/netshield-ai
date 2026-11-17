from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel

def create_topology():
    net = Mininet(controller=RemoteController)

    print("*** Adding controller")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    print("*** Adding hosts")
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    h3 = net.addHost('h3', ip='10.0.0.3')

    print("*** Adding switch")
    s1 = net.addSwitch('s1')

    print("*** Creating links")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)

    print("*** Starting network")
    net.build()
    c0.start()
    s1.start([c0])

    print("*** Running CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()