#!/usr/bin/env python3
"""show_stats.py — Lee e imprime los contadores del data plane (Thrift)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "control"))
from controller import Controller  # noqa: E402

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9090
    c = Controller(thrift_port=port)
    print("== Contadores del detector de anomalías ==")
    c.print_stats()
