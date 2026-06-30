#!/usr/bin/env python3
"""
legit.py — Generador de tráfico legítimo de fondo (Scapy).

Emula un cliente normal: un puñado de flujos hacia un servidor, a baja tasa,
muy por debajo de todos los umbrales. Sirve para comprobar que el detector NO
afecta al tráfico legítimo (verdaderos negativos) ni siquiera durante un ataque
concurrente.

Genera:
  * Algunos flujos TCP (handshake-like: SYN, luego datos con ACK).
  * Algunos flujos UDP de consulta/respuesta.

Cada flujo usa pocos paquetes, de modo que ni el CMS (flood) ni el contador de
destinos distintos (port scan) ni el contador de SYN (syn flood) se disparan.

Uso:
  legit.py --iface h3-eth0 --src 10.0.0.3 --dst 10.0.0.4 --flows 6 --pps 20
"""
import argparse
import socket
import time

from scapy.all import Ether, IP, TCP, UDP

DUMMY_DST_MAC = "00:00:00:00:00:fe"


def src_mac_for(src_ip):
    last = int(src_ip.split(".")[-1])
    return "00:00:00:00:00:%02x" % last


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--src", required=True)
    ap.add_argument("--dst", default="10.0.0.4")
    ap.add_argument("--flows", type=int, default=6)
    ap.add_argument("--pkts-per-flow", type=int, default=8)
    ap.add_argument("--pps", type=int, default=20)
    args = ap.parse_args()

    smac = src_mac_for(args.src)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((args.iface, 0))
    inter = 1.0 / args.pps if args.pps > 0 else 0

    total = 0
    for f in range(args.flows):
        sport = 50000 + f
        proto_tcp = (f % 2 == 0)
        dport = 80 if proto_tcp else 53
        # SYN inicial (TCP) — un solo SYN por flujo, no dispara syn flood
        if proto_tcp:
            syn = Ether(dst=DUMMY_DST_MAC, src=smac) / IP(src=args.src, dst=args.dst) / \
                TCP(sport=sport, dport=dport, flags="S")
            s.send(bytes(syn)); total += 1
            if inter: time.sleep(inter)
        # paquetes de datos del flujo (ACK puesto -> no cuenta como SYN)
        for i in range(args.pkts_per_flow):
            if proto_tcp:
                pkt = Ether(dst=DUMMY_DST_MAC, src=smac) / IP(src=args.src, dst=args.dst) / \
                    TCP(sport=sport, dport=dport, flags="A", seq=i) / (b"req" * 4)
            else:
                pkt = Ether(dst=DUMMY_DST_MAC, src=smac) / IP(src=args.src, dst=args.dst) / \
                    UDP(sport=sport, dport=dport) / (b"query" * 3)
            s.send(bytes(pkt)); total += 1
            if inter: time.sleep(inter)
    s.close()
    print("[legit] enviados %d paquetes en %d flujos desde %s" % (total, args.flows, args.src))


if __name__ == "__main__":
    main()
