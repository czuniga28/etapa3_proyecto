#!/usr/bin/env python3
"""
topology.py — Topología Mininet para el detector de anomalías.

  1 switch P4 (s1, BMv2) y 5 hosts:
      h1  10.0.0.1   (atacante: port scan)
      h2  10.0.0.2   (atacante: UDP flood / SYN flood)
      h3  10.0.0.3   (cliente legítimo)
      h4  10.0.0.4   (servidor / víctima legítima)
      hcpu 10.0.0.254 (colector del puerto CPU; recibe los clones-reporte)

  Puertos del switch: h1=1, h2=2, h3=3, h4=4, hcpu=5 (CPU).

Se instalan entradas ARP estáticas en malla completa para que NO se genere
tráfico ARP (broadcast), de modo que el switch reenvíe puramente por IP destino.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from p4_mininet import P4Switch, P4Host  # noqa: E402
from mininet.net import Mininet           # noqa: E402
from mininet.topo import Topo             # noqa: E402
from mininet.link import TCLink           # noqa: E402

CPU_PORT = 5
CPU_MIRROR_SESSION = 100

HOSTS = [
    # name, ip,            mac,                 port
    ("h1",   "10.0.0.1",   "00:00:00:00:00:01", 1),
    ("h2",   "10.0.0.2",   "00:00:00:00:00:02", 2),
    ("h3",   "10.0.0.3",   "00:00:00:00:00:03", 3),
    ("h4",   "10.0.0.4",   "00:00:00:00:00:04", 4),
    ("hcpu", "10.0.0.254", "00:00:00:00:00:fe", CPU_PORT),
]

# Entradas de reenvío (dst_ip, egress_port, dst_mac) — hcpu no se reenvía.
FORWARDING = [(ip, port, mac) for (name, ip, mac, port) in HOSTS if name != "hcpu"]


class AnomalyTopo(Topo):
    def __init__(self, json_path, thrift_port=9090, **kw):
        self.json_path = json_path
        self.thrift_port = thrift_port
        super(AnomalyTopo, self).__init__(**kw)

    def build(self):
        s1 = self.addSwitch("s1", cls=P4Switch, sw_path="simple_switch",
                            json_path=self.json_path, thrift_port=self.thrift_port,
                            pcap_dump=False)
        for name, ip, mac, port in HOSTS:
            h = self.addHost(name, cls=P4Host, ip="%s/24" % ip, mac=mac)
            self.addLink(h, s1, port2=port)


def build_net(json_path, thrift_port=9090):
    topo = AnomalyTopo(json_path=json_path, thrift_port=thrift_port)
    net = Mininet(topo=topo, host=P4Host, switch=P4Switch, link=TCLink,
                  controller=None)
    net.start()
    install_static_arp(net)
    return net


def install_static_arp(net):
    """Malla completa de ARP estático para evitar tráfico broadcast."""
    for name, ip, mac, port in HOSTS:
        h = net.get(name)
        for oname, oip, omac, oport in HOSTS:
            if oname != name:
                h.cmd("arp -s %s %s" % (oip, omac))


def cpu_iface():
    """Interfaz (lado switch) del puerto CPU, accesible desde el namespace raíz."""
    return "s1-eth%d" % CPU_PORT
