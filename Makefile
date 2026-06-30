# Makefile — Detección de Anomalías de Tráfico en P4 (BMv2/Mininet)
#
# Estos objetivos asumen que se ejecutan DENTRO de un entorno con la toolchain
# P4 (p4c, simple_switch, mininet, scapy). Si usas Docker, ejecútalos a través
# de ./run.sh, que monta el repo en la imagen p4lab.

P4C       ?= p4c-bm2-ss
P4_SRC     = p4src/anomaly.p4
BUILD      = build
JSON       = $(BUILD)/anomaly.json
P4INFO     = $(BUILD)/anomaly.p4info.txt

.PHONY: all build test demo clean stats

all: build

build: $(JSON)

$(JSON): $(P4_SRC)
	@mkdir -p $(BUILD)
	$(P4C) --p4v 16 --p4runtime-files $(P4INFO) -o $(JSON) $(P4_SRC)
	@echo "[ok] compilado -> $(JSON)"

test: build
	@mn -c >/dev/null 2>&1 || true
	python3 tests/run_tests.py

demo: build
	@mn -c >/dev/null 2>&1 || true
	python3 control/run_demo.py

stats:
	python3 control/show_stats.py

clean:
	@mn -c >/dev/null 2>&1 || true
	rm -rf $(BUILD) results/*.json results/*.md results/*.txt
	rm -f /tmp/*.log
	@echo "[ok] limpio"
