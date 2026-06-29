#!/usr/bin/env python3
"""
controller.py — Control plane (Thrift / simple_switch_CLI) para anomaly.p4.

Responsabilidades:
  * Poblar la tabla de reenvío (ipv4_lpm) y la lista blanca (ip_whitelist).
  * Configurar umbrales y modo de mitigación (registros).
  * Configurar la sesión de mirror (clone) hacia el puerto CPU.
  * Leer contadores/registros del data plane.
  * Sniffer del puerto CPU: recibe los clones-reporte (report_t) que el data
    plane envía al detectar una anomalía, los registra y los muestra en consola
    (visualización en tiempo real — funcionalidad opcional).

No interviene en la detección ni en la mitigación: ambas ocurren íntegramente
en el data plane. El control plane sólo configura, observa y reporta.
"""
import re
import socket
import struct
import subprocess
import sys
import threading
import time

# ----------------------------- Tipos de anomalía -----------------------------
ANOM_NAMES = {1: "PORT_SCAN", 2: "FLOOD", 3: "SYN_FLOOD"}


def ip2str(v):
    return socket.inet_ntoa(struct.pack("!I", v))


class Controller(object):
    def __init__(self, thrift_port=9090, json_path="build/anomaly.json"):
        self.thrift_port = thrift_port
        self.json_path = json_path
        # reportes recibidos: dict src_ip -> dict(type-> count), y orden temporal
        self.reports = {}
        self.report_log = []     # lista (ts, src, dst, type, estimate)
        self._sniffer = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ CLI
    def cli(self, commands):
        """Envía una lista (o string) de comandos a simple_switch_CLI."""
        if isinstance(commands, (list, tuple)):
            commands = "\n".join(commands) + "\n"
        p = subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(self.thrift_port)],
            input=commands, capture_output=True, text=True)
        return p.stdout + p.stderr

    def read_reg(self, name, index=0):
        out = self.cli("register_read %s %d" % (name, index))
        m = re.search(r"\[%d\]=\s*(\d+)" % index, out)
        return int(m.group(1)) if m else None

    def write_reg(self, name, index, value):
        self.cli("register_write %s %d %d" % (name, index, value))

    # --------------------------------------------------------------- Setup
    def setup_forwarding(self, entries):
        """entries: lista de (dst_ip, port, dst_mac)."""
        cmds = []
        for ip, port, mac in entries:
            cmds.append("table_add MyIngress.ipv4_lpm ipv4_forward %s => %d %s"
                        % (ip, port, mac))
        print(self.cli(cmds).strip().splitlines()[-1] if cmds else "")
        print("[controller] %d entradas de reenvío instaladas" % len(entries))

    def setup_whitelist(self, ips):
        if not ips:
            return
        cmds = ["table_add MyIngress.ip_whitelist set_whitelist %s =>" % ip for ip in ips]
        self.cli(cmds)
        print("[controller] lista blanca: %s" % ", ".join(ips))

    def setup_mirror(self, session, cpu_port):
        self.cli("mirroring_add %d %d" % (session, cpu_port))
        print("[controller] sesión de mirror %d -> puerto CPU %d" % (session, cpu_port))

    def set_thresholds(self, flood, scan, synflood, mitig_mode):
        self.write_reg("r_flood_threshold", 0, flood)
        self.write_reg("r_scan_threshold", 0, scan)
        self.write_reg("r_synflood_threshold", 0, synflood)
        self.write_reg("r_mitig_mode", 0, mitig_mode)
        print("[controller] umbrales: flood>%d/ventana  scan>%d dest/ventana  "
              "syn>%d/ventana  mitig_mode=%s"
              % (flood, scan, synflood, "DROP" if mitig_mode == 0 else "MARK"))

    # --------------------------------------------------------------- Stats
    def stats(self):
        names = ["c_total", "c_portscan", "c_flood", "c_synflood",
                 "c_reports", "c_mitigated", "c_marked"]
        return {n: (self.read_reg(n) or 0) for n in names}

    def print_stats(self):
        s = self.stats()
        print("  paquetes IP totales : %d" % s["c_total"])
        print("  pkts port-scan      : %d" % s["c_portscan"])
        print("  pkts flood          : %d" % s["c_flood"])
        print("  pkts syn-flood      : %d" % s["c_synflood"])
        print("  reportes a CPU      : %d" % s["c_reports"])
        print("  pkts mitigados(drop): %d" % s["c_mitigated"])
        print("  pkts marcados(DSCP) : %d" % s["c_marked"])
        return s

    # ----------------------------------------------- Sniffer de reportes CPU
    def start_report_sniffer(self, iface, verbose=True):
        """Arranca un AsyncSniffer de Scapy sobre la interfaz del puerto CPU."""
        from scapy.all import (AsyncSniffer, Ether, Packet, ByteField,
                               IntField, bind_layers)

        class Report(Packet):
            name = "Report"
            fields_desc = [ByteField("anomaly_type", 0),
                           IntField("src", 0),
                           IntField("dst", 0),
                           IntField("estimate", 0)]
        bind_layers(Ether, Report, type=0x1234)

        def handle(pkt):
            if Report not in pkt:
                return
            r = pkt[Report]
            src = ip2str(r.src)
            dst = ip2str(r.dst)
            typ = ANOM_NAMES.get(r.anomaly_type, "UNKNOWN")
            with self._lock:
                self.report_log.append((time.time(), src, dst, typ, r.estimate))
                self.reports.setdefault(src, {})
                self.reports[src][typ] = self.reports[src].get(typ, 0) + 1
            if verbose:
                print("  \033[91m[ALERTA]\033[0m  %-9s  src=%-12s dst=%-12s  estimador=%d"
                      % (typ, src, dst, r.estimate))

        self._sniffer = AsyncSniffer(iface=iface, prn=handle, store=False,
                                     filter="ether proto 0x1234")
        self._sniffer.start()
        time.sleep(0.5)
        print("[controller] sniffer de reportes activo en %s" % iface)

    def stop_report_sniffer(self):
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    def flagged_sources(self):
        """Devuelve dict src_ip -> set(tipos) de las fuentes reportadas."""
        with self._lock:
            return {src: set(d.keys()) for src, d in self.reports.items()}

    def reset_reports(self):
        with self._lock:
            self.reports = {}
            self.report_log = []
