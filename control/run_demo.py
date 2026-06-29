#!/usr/bin/env python3
"""
run_demo.py — Lanzador interactivo para la demostración / defensa oral.

Levanta la topología Mininet + BMv2, configura el control plane (reenvío,
mirror hacia CPU, umbrales) y arranca el sniffer de reportes que imprime
ALERTAS en tiempo real. Después abre la CLI de Mininet para ejecutar ataques
y tráfico legítimo en vivo.

Ejemplos dentro de la CLI de Mininet:
  mininet> h3 python3 scripts/legit.py --iface h3-eth0 --src 10.0.0.3 --dst 10.0.0.4 &
  mininet> h1 python3 scripts/attack.py --mode portscan --iface h1-eth0 --src 10.0.0.1 --net 10.0.1 --count 150 --dport 80
  mininet> h2 python3 scripts/attack.py --mode flood --iface h2-eth0 --src 10.0.0.2 --dst 10.0.0.4 --count 2000 --duration 6
  mininet> h2 python3 scripts/attack.py --mode synflood --iface h2-eth0 --src 10.0.0.2 --dst 10.0.0.4 --count 500 --duration 6
  mininet> h2 ping -c3 10.0.0.4      # mitigado (drop) mientras h2 esté marcado
  mininet> h3 ping -c3 10.0.0.4      # legítimo, no afectado

Para ver contadores del data plane sin salir:  sh python3 control/show_stats.py
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "control"))

from mininet.cli import CLI                 # noqa: E402
from mininet.log import setLogLevel         # noqa: E402
from topology import (build_net, HOSTS, CPU_MIRROR_SESSION,  # noqa: E402
                      CPU_PORT, cpu_iface)
from controller import Controller           # noqa: E402

JSON_PATH = os.path.join(ROOT, "build", "anomaly.json")


def main():
    setLogLevel("info")
    net = build_net(JSON_PATH, thrift_port=9090)

    c = Controller(thrift_port=9090, json_path=JSON_PATH)
    fwd = [(ip, port, mac) for (_, ip, mac, port) in HOSTS]
    c.setup_forwarding(fwd)
    c.setup_mirror(CPU_MIRROR_SESSION, CPU_PORT)
    # whitelist de ejemplo: descomentar para inmunizar un origen
    # c.setup_whitelist(["10.0.0.3"])
    c.set_thresholds(flood=100, scan=20, synflood=80, mitig_mode=0)
    c.start_report_sniffer(cpu_iface(), verbose=True)

    print("\n" + "=" * 70)
    print(" Topología lista. Las ALERTAS aparecerán aquí en tiempo real.")
    print(" Hosts: h1(atacante) h2(atacante) h3(legítimo) h4(víctima) hcpu(colector)")
    print(" Umbrales: flood>100  scan>20  syn>80  por ventana (~4.19 s)")
    print("=" * 70 + "\n")

    CLI(net)

    c.stop_report_sniffer()
    net.stop()


if __name__ == "__main__":
    main()
