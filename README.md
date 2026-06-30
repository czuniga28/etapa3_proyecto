# Detección de Anomalías de Tráfico en el Data Plane (P4 / BMv2)

Proyecto Final — **Redes Programables con P4, Opción B**.
Curso de Redes de Computadoras, Ciclo Lectivo 2026.

Sistema de detección y mitigación de anomalías de red **íntegramente en el plano
de datos P4** (BMv2 / Mininet). El switch analiza el tráfico en tiempo real con un
**Count-Min Sketch (CMS)** y detecta tres clases de ataque —**port scan horizontal**,
**flood (pps)** y **SYN flood**— aplicando mitigación (drop o marcado DSCP) **sin
intervención del control plane**. El control plane sólo configura umbrales/tablas,
lee contadores y recibe reportes (clones hacia un puerto CPU).

---

## 1. Estructura del repositorio

```
.
├── p4src/anomaly.p4          # Programa P4 (parsers, CMS, detección, mitigación, clone-report)
├── control/
│   ├── p4_mininet.py         # Clases P4Switch / P4Host para Mininet
│   ├── topology.py           # Topología (1 switch + 5 hosts) y ARP estático
│   ├── controller.py         # Control plane: tablas, umbrales, contadores, sniffer de reportes
│   ├── run_demo.py           # Lanzador interactivo (CLI Mininet) para la defensa oral
│   └── show_stats.py         # Imprime los contadores del data plane
├── scripts/
│   ├── attack.py             # Generador de ataques: portscan / flood / synflood (Scapy)
│   └── legit.py              # Generador de tráfico legítimo de fondo (Scapy)
├── tests/run_tests.py        # Banco de pruebas automático + análisis TP/FP/TN/FN
├── results/                  # Resultados generados (precision.md, results.json, summary.txt)
├── docs/informe.md           # Informe técnico
├── Makefile                  # build / test / demo / clean
├── run.sh                    # Envoltorio Docker (imagen p4lab)
└── README.md
```

## 2. Requisitos

- **Toolchain P4**: `p4c` (p4c-bm2-ss), `simple_switch` + `simple_switch_CLI` (BMv2),
  `mininet`, Python 3 con `scapy`.
- La forma más sencilla de obtener todo es la imagen Docker **`p4lab`** (incluye
  p4c, BMv2, Mininet y Scapy). Todos los comandos pueden ejecutarse a través de
  `run.sh`, que monta este repositorio en `/work` dentro del contenedor con
  `--privileged` (necesario para los namespaces/veth de Mininet).

> Probado sobre `p4lab:latest` (BMv2 v1model, p4c, Mininet, Python 3.10, Scapy 2.4.4),
> incluso bajo emulación `linux/amd64` en un host arm64 (macOS + Docker Desktop).

## 3. Instalación y ejecución paso a paso

### Opción A — con Docker (recomendada)

```bash
# 1. Compilar el programa P4
./run.sh build

# 2. Ejecutar TODA la batería de pruebas automáticas (detección + mitigación)
./run.sh test

# 3. Demostración interactiva (CLI de Mininet) para la defensa
./run.sh demo
```

### Opción B — dentro de un entorno P4 nativo

```bash
make build      # compila p4src/anomaly.p4 -> build/anomaly.json
sudo make test  # banco de pruebas (requiere root para Mininet)
sudo make demo  # CLI interactiva
make clean      # limpia artefactos y libera Mininet
```

### Qué hace `make test`

Levanta la topología, configura el control plane y ejecuta **4 escenarios**
(+ verificación del modo de marcado DSCP), midiendo precisión de detección
(TP/FP/TN/FN), efectividad de la mitigación y latencia del tráfico legítimo.
Genera en `results/`:

- `precision.md` — tabla de precisión y mitigación.
- `results.json` — resultados completos en JSON.
- `summary.txt` — métricas agregadas.

Resultado de referencia obtenido en este entorno:

```
TP=5  FP=0  TN=4  FN=0   precision=1.000  recall=1.000  FPR=0.000
Mitigación: legítimo h3->h4 = 0% pérdida; atacante h2->h4 = 100% pérdida (drop)
```

## 4. Topología

```
        h1 (10.0.0.1)  ── atacante (port scan)
        h2 (10.0.0.2)  ── atacante (flood / syn flood)
        h3 (10.0.0.3)  ── cliente legítimo          ┐
        h4 (10.0.0.4)  ── servidor / víctima        ├── s1 (switch P4 BMv2)
        hcpu (10.0.0.254) ── colector del puerto CPU ┘   (recibe clones-reporte)
```

Puertos del switch: `h1=1, h2=2, h3=3, h4=4, hcpu=5 (CPU)`. Se instalan entradas
**ARP estáticas en malla completa** para que no se genere tráfico broadcast y el
switch reenvíe puramente por IP destino.

## 5. Demostración interactiva (defensa oral)

Tras `./run.sh demo` aparece la CLI de Mininet con el sniffer de reportes activo
(las **ALERTAS** se imprimen en tiempo real). Comandos sugeridos (parámetros
probados):

```text
# tráfico legítimo de fondo (no debe verse afectado)
mininet> h3 python3 scripts/legit.py --iface h3-eth0 --src 10.0.0.3 --dst 10.0.0.4 &

# port scan horizontal  -> ALERTA PORT_SCAN para 10.0.0.1
mininet> h1 python3 scripts/attack.py --mode portscan --iface h1-eth0 --src 10.0.0.1 --net 10.0.1 --count 150 --dport 80

# UDP flood (flujo único, sostenido) -> ALERTA FLOOD para 10.0.0.2
mininet> h2 python3 scripts/attack.py --mode flood --iface h2-eth0 --src 10.0.0.2 --dst 10.0.0.4 --count 2000 --duration 6 &

# durante el flood: el atacante queda mitigado, el legítimo no
mininet> h2 ping -c 3 10.0.0.4     # ~100% pérdida (drop)
mininet> h3 ping -c 3 10.0.0.4     # 0% pérdida

# SYN flood -> ALERTA SYN_FLOOD para 10.0.0.2
mininet> h2 python3 scripts/attack.py --mode synflood --iface h2-eth0 --src 10.0.0.2 --dst 10.0.0.4 --count 500 --duration 6 &

# leer contadores del data plane en cualquier momento
mininet> sh python3 control/show_stats.py
```

> **Nota sobre la tasa de envío.** BMv2 en modo emulado procesa a baja tasa; un
> envío instantáneo de muchos paquetes satura el veth y se pierden en ráfaga. Por
> eso los floods usan `--duration` (envío sostenido) y el port scan un `--count`
> holgado. Los umbrales se expresan **por ventana temporal (~4.19 s)**, no por
> segundo absoluto, lo que da robustez frente a esa variabilidad.

## 6. Configuración (umbrales y mitigación)

Los umbrales viven en **registros P4** y los fija el control plane en caliente
(`controller.set_thresholds`). Valores por defecto:

| Parámetro | Registro | Valor | Significado |
|-----------|----------|-------|-------------|
| Flood     | `r_flood_threshold` | 100 | paquetes de un flujo (5-tupla) por ventana |
| Port scan | `r_scan_threshold`  | 20  | destinos `(IP,puerto)` distintos por origen y ventana |
| SYN flood | `r_synflood_threshold` | 80 | SYN de un par (origen,víctima) por ventana |
| Mitigación| `r_mitig_mode` | 0 | `0`=DROP, `1`=marcar DSCP |

La **lista blanca** (`controller.setup_whitelist([...])`) inmuniza IPs concretas
de toda detección/mitigación (ver ejemplo comentado en `control/run_demo.py`).

## 7. Funcionalidades

**Obligatorias** — todas implementadas:

- ✅ Count-Min Sketch (3 filas × 4096 columnas) con ventana temporal.
- ✅ Detección de port scan horizontal (destinos distintos por origen).
- ✅ Detección de flood por umbral de pps configurable.
- ✅ Mitigación en el data plane: drop **o** marcado DSCP.
- ✅ Reporte al control plane mediante **clone** del paquete hacia el puerto CPU.

**Opcionales** — implementadas (+5% c/u):

- ✅ Detección de **SYN flood** (conexiones half-open con registers).
- ✅ **Lista blanca** de IPs inmunes a la detección.
- ✅ **Visualización en tiempo real** de los flujos sospechosos en consola
  (sniffer de reportes del controlador).

## 8. Declaración de uso de IA generativa

Conforme a la sección 5 de la consigna, se declara el uso de IA generativa
(asistente de código tipo Claude) como apoyo en la elaboración de este proyecto:

- **Generado con asistencia de IA y verificado por el autor**: el andamiaje de la
  topología Mininet (`p4_mininet.py`, basado en el patrón público de
  `p4lang/tutorials`), borradores del controlador y de los scripts de prueba, y la
  redacción del informe.
- **Diseño y decisiones técnicas propias**: la arquitectura del pipeline P4
  (esquema del CMS con ventana perezosa por época, atribución del SYN flood por par
  origen-víctima, separación scan/flood, mecanismo de clone-report), la elección de
  umbrales y la metodología de evaluación.
- **Verificación**: todo el código fue **compilado y ejecutado** end-to-end sobre
  BMv2/Mininet; los resultados de `make test` (precisión 1.0, FPR 0.0, mitigación
  efectiva) son reproducibles con los comandos de este README. Ninguna afirmación
  del informe se tomó sin respaldo experimental.

No se incorporó código de terceros más allá del patrón de integración Mininet↔BMv2
citado, muy por debajo del 20% del total.

## 9. Limpieza

```bash
./run.sh make clean      # o, en entorno nativo:  sudo make clean
```
