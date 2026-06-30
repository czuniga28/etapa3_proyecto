#!/usr/bin/env python3
"""
attack.py — Generador de tráfico de ataque (Scapy) para validar la detección.

Modos:
  portscan  : port scan horizontal — una IP origen hacia muchas (IP,puerto)
              destino distintas (SYN TCP).
  flood     : UDP flood — un único flujo (5-tupla fija) a alta tasa.
  synflood  : SYN flood — muchos SYN hacia una misma víctima, variando el
              puerto origen (5-tuplas distintas) para emular half-open.

Los paquetes se serializan con Scapy y se envían por un socket AF_PACKET en
crudo (rápido y determinista incluso bajo emulación). La dirección MAC destino
es irrelevante: el switch P4 reenvía por IP destino.

Uso:
  attack.py --mode flood    --iface h2-eth0 --src 10.0.0.2 --dst 10.0.0.4 \
            --count 1500 --dport 9999 --sport 4444
  attack.py --mode portscan --iface h1-eth0 --src 10.0.0.1 \
            --net 10.0.1 --count 120 --dport 80
  attack.py --mode synflood --iface h2-eth0 --src 10.0.0.2 --dst 10.0.0.4 \
            --count 600 --dport 80
"""
import argparse
import socket
import time

from scapy.all import Ether, IP, TCP, UDP

DUMMY_DST_MAC = "00:00:00:00:00:fe"


def raw_socket(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((iface, 0))
    return s


def src_mac_for(src_ip):
    # h1->...:01, h2->...:02, etc. según el último octeto.
    last = int(src_ip.split(".")[-1])
    return "00:00:00:00:00:%02x" % last


def gen_flood(src, dst, sport, dport, count):
    base = Ether(dst=DUMMY_DST_MAC, src=src_mac_for(src)) / \
        IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / (b"F" * 32)
    raw = bytes(base)
    return [raw] * count


def gen_portscan(src, net, dport, count):
    out = []
    for i in range(count):
        dst = "%s.%d" % (net, 1 + (i % 254))
        # variar también el puerto destino cada vuelta de /24 -> más destinos distintos
        dp = dport + (i // 254)
        pkt = Ether(dst=DUMMY_DST_MAC, src=src_mac_for(src)) / \
            IP(src=src, dst=dst) / TCP(sport=44444, dport=dp, flags="S")
        out.append(bytes(pkt))
    return out


def gen_synflood(src, dst, dport, count):
    out = []
    for i in range(count):
        sport = 1024 + (i % 60000)
        pkt = Ether(dst=DUMMY_DST_MAC, src=src_mac_for(src)) / \
            IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
        out.append(bytes(pkt))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True,
                    choices=["portscan", "flood", "synflood"])
    ap.add_argument("--iface", required=True)
    ap.add_argument("--src", required=True)
    ap.add_argument("--dst", default="10.0.0.4")
    ap.add_argument("--net", default="10.0.1")
    ap.add_argument("--count", type=int, default=1000)
    ap.add_argument("--sport", type=int, default=4444)
    ap.add_argument("--dport", type=int, default=9999)
    ap.add_argument("--pps", type=int, default=0,
                    help="limitar a N paquetes/segundo (0 = sin límite)")
    ap.add_argument("--duration", type=float, default=0,
                    help="enviar de forma sostenida durante N segundos (0 = una sola pasada)")
    args = ap.parse_args()

    if args.mode == "flood":
        pkts = gen_flood(args.src, args.dst, args.sport, args.dport, args.count)
    elif args.mode == "portscan":
        pkts = gen_portscan(args.src, args.net, args.dport, args.count)
    else:
        pkts = gen_synflood(args.src, args.dst, args.dport, args.count)

    s = raw_socket(args.iface)
    inter = (1.0 / args.pps) if args.pps > 0 else 0
    t0 = time.time()
    sent = 0
    end = t0 + args.duration if args.duration > 0 else None
    while True:
        for raw in pkts:
            s.send(raw)
            sent += 1
            if inter:
                time.sleep(inter)
        if end is None or time.time() >= end:
            break
    dt = time.time() - t0
    s.close()
    print("[attack:%s] enviados %d paquetes en %.3fs (%.0f pps) src=%s"
          % (args.mode, sent, dt, sent / dt if dt else 0, args.src))


if __name__ == "__main__":
    main()
