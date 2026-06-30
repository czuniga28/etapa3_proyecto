#!/usr/bin/env python3
"""
run_tests.py — Banco de pruebas automático del detector de anomalías.

Levanta la topología Mininet + BMv2, configura el control plane y ejecuta una
batería de escenarios, midiendo:

  * Precisión de detección: TP / FP / TN / FN por escenario y agregado.
  * Mitigación efectiva: pérdida del atacante (debe ser alta) frente a pérdida
    del tráfico legítimo (debe ser ~0), incluso con ataque concurrente.
  * Latencia del tráfico legítimo: RTT antes vs. durante el ataque.

Genera artefactos en results/: results.json, precision.md, summary.txt.

Debe ejecutarse como root dentro del contenedor p4lab (Mininet + BMv2):
    python3 tests/run_tests.py
"""
import json
import os
import re
import sys
import time

os.environ.setdefault("SHELL", "/bin/bash")


def bg(host, cmd):
    """Lanza un comando en segundo plano dentro del namespace del host."""
    return host.popen([cmd], shell=True)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "control"))

from mininet.log import setLogLevel                    # noqa: E402
import topology                                        # noqa: E402
from topology import (build_net, FORWARDING, HOSTS,    # noqa: E402
                      CPU_MIRROR_SESSION, CPU_PORT, cpu_iface)
from controller import Controller                      # noqa: E402

JSON_PATH = os.path.join(ROOT, "build", "anomaly.json")
RESULTS_DIR = os.path.join(ROOT, "results")

FLOOD_TH = 100      # paquetes por ventana (~4.19 s) en un mismo flujo
SCAN_TH = 20        # destinos distintos por ventana desde un mismo origen
SYN_TH = 80         # SYN por ventana hacia una misma víctima
WINDOW_S = 4.3      # duración aproximada de la ventana temporal (2^22 us)

MAC = {ip: mac for (_, ip, mac, _) in HOSTS}


def macfix(ip):
    return MAC[ip]


def parse_loss(ping_out):
    m = re.search(r"(\d+)% packet loss", ping_out)
    return int(m.group(1)) if m else 100


def parse_rtt(ping_out):
    m = re.search(r"=\s*[\d.]+/([\d.]+)/", ping_out)
    return float(m.group(1)) if m else None


def attack_cmd(mode, host, src, **kw):
    base = ("python3 %s/scripts/attack.py --mode %s --iface %s-eth0 --src %s "
            % (ROOT, mode, host, src))
    for k, v in kw.items():
        base += "--%s %s " % (k.replace("_", "-"), v)
    return base


def legit_cmd(host, src, dst="10.0.0.4", flows=6, pps=25):
    return ("python3 %s/scripts/legit.py --iface %s-eth0 --src %s --dst %s "
            "--flows %d --pps %d" % (ROOT, host, src, dst, flows, pps))


def confusion(flagged, attackers, benign):
    """flagged: set de IPs reportadas. Devuelve TP,FP,TN,FN."""
    tp = len([a for a in attackers if a in flagged])
    fn = len([a for a in attackers if a not in flagged])
    fp = len([b for b in benign if b in flagged])
    tn = len([b for b in benign if b not in flagged])
    return tp, fp, tn, fn


def main():
    setLogLevel("output")
    os.makedirs(RESULTS_DIR, exist_ok=True)

    print("=" * 70)
    print(" Levantando topología Mininet + BMv2 ...")
    print("=" * 70)
    net = build_net(JSON_PATH, thrift_port=9090)

    c = Controller(thrift_port=9090, json_path=JSON_PATH)
    # reenvío para los 5 hosts (incluye hcpu para que ping a hcpu funcione)
    fwd = [(ip, port, mac) for (_, ip, mac, port) in HOSTS]
    c.setup_forwarding(fwd)
    c.setup_mirror(CPU_MIRROR_SESSION, CPU_PORT)
    c.set_thresholds(FLOOD_TH, SCAN_TH, SYN_TH, mitig_mode=0)
    c.start_report_sniffer(cpu_iface(), verbose=True)

    h1, h2, h3, h4 = net.get("h1"), net.get("h2"), net.get("h3"), net.get("h4")

    results = {"scenarios": [], "thresholds": {
        "flood_per_window": FLOOD_TH, "scan_per_window": SCAN_TH,
        "syn_per_window": SYN_TH, "window_s_approx": 1.05}}

    # ---------------------------------------------------- conectividad base
    print("\n[baseline] verificando conectividad legítima h3 -> h4 ...")
    out = h3.cmd("ping -c 4 -i 0.3 -W 1 10.0.0.4")
    base_loss = parse_loss(out)
    base_rtt = parse_rtt(out)
    print("  pérdida=%d%%  rtt_avg=%s ms" % (base_loss, base_rtt))
    results["baseline"] = {"loss_pct": base_loss, "rtt_avg_ms": base_rtt}

    def settle():
        time.sleep(WINDOW_S + 1.0)  # dejar expirar la ventana entre escenarios
        c.reset_reports()

    # ======================================================== ESCENARIO 1
    print("\n" + "=" * 70)
    print(" ESCENARIO 1 — Port scan horizontal (atacante h1) + legítimo h3")
    print("=" * 70)
    settle()
    s_before = c.stats()
    p_legit = bg(h3, legit_cmd("h3", "10.0.0.3"))
    p_atk = bg(h1, attack_cmd("portscan", "h1", "10.0.0.1",
                                net="10.0.1", count=150, dport=80))
    p_atk.wait(); p_legit.wait()
    time.sleep(1.0)
    flagged = c.flagged_sources()
    tp, fp, tn, fn = confusion(set(flagged), ["10.0.0.1"], ["10.0.0.3"])
    s_after = c.stats()
    print("  fuentes reportadas: %s" % dict(flagged))
    results["scenarios"].append({
        "name": "Port scan horizontal", "attackers": ["10.0.0.1"],
        "benign": ["10.0.0.3"], "flagged": {k: list(v) for k, v in flagged.items()},
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "detections_delta": s_after["c_portscan"] - s_before["c_portscan"]})

    # ======================================================== ESCENARIO 2
    print("\n" + "=" * 70)
    print(" ESCENARIO 2 — UDP flood (atacante h2 -> h4) + legítimo h3")
    print("=" * 70)
    settle()
    s_before = c.stats()
    p_legit = bg(h3, legit_cmd("h3", "10.0.0.3"))
    p_atk = bg(h2, attack_cmd("flood", "h2", "10.0.0.2", dst="10.0.0.4",
                                count=2000, sport=4444, dport=9999, duration=6))
    p_atk.wait(); p_legit.wait()
    time.sleep(1.0)
    flagged = c.flagged_sources()
    tp, fp, tn, fn = confusion(set(flagged), ["10.0.0.2"], ["10.0.0.3"])
    s_after = c.stats()
    print("  fuentes reportadas: %s" % dict(flagged))
    results["scenarios"].append({
        "name": "UDP flood (5-tupla)", "attackers": ["10.0.0.2"],
        "benign": ["10.0.0.3"], "flagged": {k: list(v) for k, v in flagged.items()},
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "detections_delta": s_after["c_flood"] - s_before["c_flood"]})

    # ======================================================== ESCENARIO 3
    print("\n" + "=" * 70)
    print(" ESCENARIO 3 — SYN flood (atacante h2 -> víctima h4) + legítimo h3")
    print("=" * 70)
    settle()
    s_before = c.stats()
    p_legit = bg(h3, legit_cmd("h3", "10.0.0.3"))
    p_atk = bg(h2, attack_cmd("synflood", "h2", "10.0.0.2", dst="10.0.0.4",
                                count=500, dport=80, duration=6))
    p_atk.wait(); p_legit.wait()
    time.sleep(1.0)
    flagged = c.flagged_sources()
    tp, fp, tn, fn = confusion(set(flagged), ["10.0.0.2"], ["10.0.0.3"])
    s_after = c.stats()
    print("  fuentes reportadas: %s" % dict(flagged))
    results["scenarios"].append({
        "name": "SYN flood (half-open)", "attackers": ["10.0.0.2"],
        "benign": ["10.0.0.3"], "flagged": {k: list(v) for k, v in flagged.items()},
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "detections_delta": s_after["c_synflood"] - s_before["c_synflood"]})

    # ======================================================== ESCENARIO 4
    print("\n" + "=" * 70)
    print(" ESCENARIO 4 — Ataque mixto + medición de mitigación")
    print("   (h1 port scan, h2 flood, h3 legítimo simultáneos)")
    print("=" * 70)
    settle()
    s_before = c.stats()
    # lanzar atacantes SOSTENIDOS en segundo plano (duración) y medir durante el ataque
    p_scan = bg(h1, attack_cmd("portscan", "h1", "10.0.0.1", net="10.0.1",
                               count=400, dport=80))
    p_flood = bg(h2, attack_cmd("flood", "h2", "10.0.0.2", dst="10.0.0.4",
                                count=4000, sport=4444, dport=9999, duration=8))
    time.sleep(1.5)  # dar tiempo a que se disparen y consoliden las anomalías
    # tráfico legítimo (ping) DURANTE el ataque -> NO debe verse afectado
    legit_out = h3.cmd("ping -c 6 -i 0.25 -W 1 10.0.0.4")
    legit_loss = parse_loss(legit_out); legit_rtt = parse_rtt(legit_out)
    # tráfico del atacante h2 (ping) DURANTE el ataque -> debe ser mitigado (drop)
    atk_out = h2.cmd("ping -c 6 -i 0.25 -W 1 10.0.0.4")
    atk_loss = parse_loss(atk_out)
    p_scan.wait(); p_flood.wait()
    time.sleep(1.0)
    flagged = c.flagged_sources()
    tp, fp, tn, fn = confusion(set(flagged), ["10.0.0.1", "10.0.0.2"], ["10.0.0.3"])
    s_after = c.stats()
    print("  fuentes reportadas: %s" % dict(flagged))
    print("  legítimo h3->h4 : pérdida=%d%% rtt=%s ms" % (legit_loss, legit_rtt))
    print("  atacante h2->h4 : pérdida=%d%% (mitigado)" % atk_loss)
    print("  paquetes mitigados (drop) en data plane: %d"
          % (s_after["c_mitigated"] - s_before["c_mitigated"]))
    results["scenarios"].append({
        "name": "Ataque mixto + mitigación", "attackers": ["10.0.0.1", "10.0.0.2"],
        "benign": ["10.0.0.3"], "flagged": {k: list(v) for k, v in flagged.items()},
        "TP": tp, "FP": fp, "TN": tn, "FN": fn,
        "legit_loss_pct": legit_loss, "legit_rtt_ms": legit_rtt,
        "attacker_loss_pct": atk_loss,
        "mitigated_pkts": s_after["c_mitigated"] - s_before["c_mitigated"]})

    # ============================================ verificación modo MARK (DSCP)
    print("\n[extra] verificando mitigación por marcado DSCP (mode=1) ...")
    settle()
    c.set_thresholds(FLOOD_TH, SCAN_TH, SYN_TH, mitig_mode=1)
    s_before = c.stats()
    p = bg(h2, attack_cmd("flood", "h2", "10.0.0.2", dst="10.0.0.4",
                            count=3000, sport=7777, dport=8888))
    p.wait(); time.sleep(1.0)
    s_after = c.stats()
    marked = s_after["c_marked"] - s_before["c_marked"]
    print("  paquetes marcados DSCP: %d" % marked)
    results["mark_mode_marked_pkts"] = marked
    c.set_thresholds(FLOOD_TH, SCAN_TH, SYN_TH, mitig_mode=0)

    # --------------------------------------------------------- agregados
    agg = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for s in results["scenarios"]:
        for k in agg:
            agg[k] += s[k]
    tp, fp, tn, fn = agg["TP"], agg["FP"], agg["TN"], agg["FN"]
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    results["aggregate"] = {**agg, "precision": precision, "recall": recall,
                            "false_positive_rate": fpr}

    print("\n" + "#" * 70)
    print(" RESUMEN GLOBAL")
    print("#" * 70)
    print("  TP=%d  FP=%d  TN=%d  FN=%d" % (tp, fp, tn, fn))
    print("  precision=%.3f  recall=%.3f  FPR=%.3f" % (precision, recall, fpr))
    print("\n  Contadores finales del data plane:")
    c.print_stats()

    write_artifacts(results)
    net.stop()
    c.stop_report_sniffer()

    # criterio de éxito global
    ok = (fp == 0 and fn == 0 and tp >= 5 and base_loss == 0
          and results["scenarios"][3]["legit_loss_pct"] == 0
          and results["scenarios"][3]["attacker_loss_pct"] > 0
          and marked > 0)
    print("\n  RESULTADO: %s" % ("PASS ✅" if ok else "FALLOS ❌"))
    sys.exit(0 if ok else 1)


def write_artifacts(results):
    with open(os.path.join(RESULTS_DIR, "results.json"), "w") as f:
        json.dump(results, f, indent=2)

    # precision.md
    lines = ["# Análisis de Precisión de Detección", "",
             "Umbrales: flood>%d pkt/ventana, scan>%d dest/ventana, syn>%d/ventana "
             "(ventana ≈ 4.19 s = 2^22 us).""" % (FLOOD_TH, SCAN_TH, SYN_TH), "",
             "| Escenario | Atacantes | Detecciones (pkt) | TP | FP | TN | FN |",
             "|-----------|-----------|-------------------|----|----|----|----|"]
    for s in results["scenarios"]:
        lines.append("| %s | %s | %s | %d | %d | %d | %d |" % (
            s["name"], ",".join(s["attackers"]),
            s.get("detections_delta", "—"), s["TP"], s["FP"], s["TN"], s["FN"]))
    a = results["aggregate"]
    lines += ["",
              "**Agregado:** TP=%d, FP=%d, TN=%d, FN=%d" % (a["TP"], a["FP"], a["TN"], a["FN"]),
              "",
              "- Precisión = %.3f" % a["precision"],
              "- Recall (sensibilidad) = %.3f" % a["recall"],
              "- Tasa de falsos positivos (FPR) = %.3f" % a["false_positive_rate"],
              "",
              "## Mitigación (Escenario 4 — ataque mixto)",
              "",
              "| Métrica | Valor |",
              "|---------|-------|",
              "| Pérdida tráfico legítimo h3→h4 | %d%% |" % results["scenarios"][3]["legit_loss_pct"],
              "| RTT legítimo h3→h4 durante ataque | %s ms |" % results["scenarios"][3]["legit_rtt_ms"],
              "| Pérdida tráfico atacante h2→h4 (mitigado) | %d%% |" % results["scenarios"][3]["attacker_loss_pct"],
              "| Paquetes descartados por mitigación | %d |" % results["scenarios"][3]["mitigated_pkts"],
              "| Paquetes marcados DSCP (modo mark) | %d |" % results.get("mark_mode_marked_pkts", 0),
              "",
              "RTT legítimo base (sin ataque): %s ms; pérdida base: %d%%."
              % (results["baseline"]["rtt_avg_ms"], results["baseline"]["loss_pct"])]
    with open(os.path.join(RESULTS_DIR, "precision.md"), "w") as f:
        f.write("\n".join(lines) + "\n")

    with open(os.path.join(RESULTS_DIR, "summary.txt"), "w") as f:
        f.write(json.dumps(results["aggregate"], indent=2) + "\n")
    print("\n[artefactos] results/results.json, results/precision.md, results/summary.txt")


if __name__ == "__main__":
    main()
