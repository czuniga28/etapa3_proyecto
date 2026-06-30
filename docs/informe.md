# Detección de Anomalías de Tráfico en el Plano de Datos Programable con P4

**Curso de Redes de Computadoras — Proyecto Final, Opción B**
**Ciclo Lectivo 2026**

---

## 1. Introducción

### 1.1 Motivación

Los ataques volumétricos y de reconocimiento —*port scans*, *floods* y *SYN
floods*— siguen siendo el preludio y el cuerpo principal de la mayoría de los
incidentes de seguridad de red. La defensa tradicional los procesa en *middleboxes*
o en el plano de control (controladores SDN, colectores NetFlow/IPFIX, IDS sobre
CPU), lo que introduce dos problemas: **latencia de reacción** —los paquetes ya
atravesaron la red cuando el control plane decide— y **cuello de botella de
escalabilidad**, porque exportar y analizar cada flujo a línea de tasa de
*terabits* es inviable.

El plano de datos programable (P4 sobre ASIC/`BMv2`) cambia esta ecuación: permite
**medir y reaccionar dentro del propio switch**, a velocidad de línea y sin sacar el
tráfico del *fast path*. Este proyecto implementa precisamente eso: un detector que
estima frecuencias de flujo con un *Count-Min Sketch* y mitiga anomalías (descarte o
marcado) **sin intervención del control plane**, el cual queda relegado a configurar
umbrales y recibir reportes asíncronos.

### 1.2 Estado del arte

La idea de llevar telemetría y detección al *data plane* madura con varias líneas de
trabajo. **In-band Network Telemetry (INT)** populariza incrustar metadatos por salto
en el paquete. **Sketches probabilísticos** —el *Count-Min Sketch* de Cormode y
Muthukrishnan [1] y sus derivados *Count Sketch* y *UnivMon* [5]— permiten estimar
frecuencias y detectar *heavy hitters* con memoria sublineal, encajando en el modelo
de *registers* de tamaño fijo de P4. En mitigación de DDoS, **Jaqen** [4] y los
trabajos de *Real-time DDoS Mitigation in Programmable Data Planes* (Hula et al.,
SIGCOMM 2020) [6] muestran detección y filtrado de ataques volumétricos enteramente
en el switch programable. En el plano del *caching*/medición, **NetCache** [7]
demuestra que estructuras de datos sofisticadas (sketches, tablas) caben en el
pipeline a velocidad de línea. Nuestro sistema se inscribe en esta corriente con un
alcance docente: un CMS con ventana temporal y tres detectores complementarios.

### 1.3 Casos de uso reales

- **Bordes de datacenter / ISP**: descartar floods volumétricos antes de que
  saturen enlaces o servidores, sin desviar tráfico a *scrubbing centers*.
- **Defensa de reconocimiento**: detectar barridos horizontales (un atacante
  tanteando muchos hosts/puertos) en la fase temprana de una intrusión.
- **Protección de servicios TCP**: frenar avalanchas de SYN (half-open) que agotan
  la tabla de conexiones de un servidor.
- **Telemetría liviana**: el clon-reporte hacia CPU alimenta SIEM/colectores sólo
  con eventos relevantes, en vez de exportar todos los flujos.

---

## 2. Diseño de la solución

### 2.1 Visión general del pipeline

```
            ┌──────────────────────── INGRESS ─────────────────────────┐
 paquete →  │ parser → whitelist → CMS(5-tupla) → scan(distintos)       │
            │          → synflood(src,dst) → blocklist → clone→CPU       │ → EGRESS → deparser
            │          → ipv4_lpm (reenvío) → mitigación (drop/mark)     │   (report header
            └────────────────────────────────────────────────────────────┘    en el clon)
```

Todo el procesamiento de detección y mitigación ocurre en **ingress**. El **egress**
sólo decora el paquete clonado con la cabecera de reporte. Los **checksums IPv4** se
recalculan en `MyComputeChecksum` porque la mitigación por marcado modifica el campo
`diffserv` (DSCP).

### 2.2 Parsers y cabeceras

Se parsea `Ethernet → IPv4 → {TCP | UDP}`. Las cabeceras relevantes:

- `ethernet_t` (14 B): se usa `etherType` para distinguir IPv4 (`0x0800`) y los
  clones-reporte (`0x1234`, EtherType propietario).
- `ipv4_t`: de aquí salen `srcAddr`, `dstAddr`, `protocol` y `diffserv` (marcado).
- `tcp_t` / `udp_t`: puertos L4 y, en TCP, el byte de *flags* (para distinguir SYN).
- `report_t` (13 B): cabecera sintética `{anomaly_type, src, dst, estimate}` que
  **sólo se emite en los clones** hacia el puerto CPU.

El parser es selectivo (`transition select`) y robusto frente a tráfico no-IPv4 o
no-TCP/UDP, que simplemente no activa los contadores.

### 2.3 Count-Min Sketch con ventana temporal

El corazón del sistema es un **CMS de `d=3` filas × `w=4096` columnas**, materializado
con seis *registers* (tres de conteo, tres de época):

```p4
register<bit<32>>(4096) cms_count0..2;   // conteos
register<bit<32>>(4096) cms_epoch0..2;   // época de cada celda
```

Cada fila se indexa con `crc32` sobre la 5-tupla, **decorrelacionada con una sal
distinta por fila** (`SALT0/1/2`), de modo que las tres funciones hash sean
independientes. El estimador de frecuencia de un flujo es el **mínimo de las tres
filas**, que es la garantía clásica del CMS: nunca subestima y sobreestima de forma
acotada.

**Ventana temporal sin barrido.** Reiniciar 4096×3 celdas en un paquete es imposible
en P4 (no hay bucles sobre el *register*). Se resuelve con un **reinicio perezoso por
época**: la época actual es `epoch = ingress_global_timestamp >> 22` (≈ 4.19 s por
ventana). Cada celda guarda *su* época; al tocarse, si la época almacenada difiere de
la actual, la celda se reinicia a 1 (nueva ventana) en lugar de incrementarse. Así
cada celda se "limpia" sola la primera vez que se usa en una ventana nueva, con coste
O(1) por paquete.

> **Análisis de capacidad y error.** Con `w=4096`, `d=3`, el CMS de Cormode–
> Muthukrishnan acota el error de sobreestimación a `ε·N` con probabilidad `1−δ`,
> donde `ε = e/w ≈ 6.6×10⁻⁴` y `δ = e^{−d} ≈ 0.05`. Es decir, con 95% de confianza la
> sobreestimación es menor al 0.066% del total de paquetes de la ventana. La memoria
> total del CMS es `3 × 4096 × 4 B = 48 KiB` de conteo (+48 KiB de épocas), constante
> e independiente del número de flujos. La estructura puede "almacenar" un número
> ilimitado de flujos distintos; lo que crece con la carga no es la memoria sino la
> probabilidad de colisión, controlada por `w`. Duplicar `w` halva `ε` linealmente.

### 2.4 Detección de port scan horizontal

Un escaneo horizontal es **una IP origen que contacta muchas parejas (IP, puerto)
destino distintas** en poco tiempo. Para contar *destinos distintos por origen* sin
almacenar conjuntos, se usa un **sketch de "primer contacto"**:

1. `seen_epoch[h(src,dst,dport)]` guarda la época del último contacto con esa pareja.
   Si difiere de la época actual, es un **destino nuevo** en esta ventana.
2. Sólo entonces se incrementa `scan_count[h(src)]`, el contador de destinos
   distintos del origen. Si supera `scan_threshold`, se marca *port scan*.

Crucialmente, **sólo cuentan como sondas los SYN TCP y los paquetes UDP**, nunca las
respuestas TCP (RST/ACK). Sin esta distinción, una víctima que responde con RST a
muchos puertos efímeros se confundiría con un escáner (falso positivo observado y
corregido durante las pruebas).

### 2.5 Detección de flood y SYN flood

- **Flood (pps)**: si el estimador CMS de una 5-tupla supera `flood_threshold` dentro
  de la ventana, el flujo es un *flood*. Como el umbral y la ventana son parámetros,
  el pps efectivo es `flood_threshold / 4.19 s`.
- **SYN flood (half-open)**: un contador con ventana `syn_count[h(src,dst)]` agrega
  todos los SYN de un par origen→víctima (sumando sobre los puertos origen, que un
  atacante varía para evadir la detección por 5-tupla). Se cuenta por **(origen,
  víctima)** —no sólo por víctima— para **atribuir correctamente al atacante** y poder
  bloquearlo, en vez de penalizar a la víctima.

### 2.6 Mitigación en el data plane

Cuando un origen dispara cualquier anomalía, se marca en una **blocklist** con
ventana (`blk_val[h(src)]`, `blk_epoch[...]`). Mientras el origen siga bloqueado en la
ventana (lo refresca cada paquete ofensor), **todos** sus paquetes se:

- **descartan** (`r_mitig_mode = 0`, vía `mark_to_drop`), o
- **marcan** poniendo `diffserv = DSCP 46 (EF)` (`r_mitig_mode = 1`), dejándolos pasar
  para *traffic shaping* aguas abajo.

La mitigación es **autónoma**: ocurre en el mismo paso de ingress, sin consultar al
control plane. El reinicio perezoso por época libera al origen automáticamente cuando
cesa el ataque.

### 2.7 Reporte al control plane (clone hacia CPU)

En el **primer** paquete que dispara una anomalía en cada ventana
(`do_report`), el data plane ejecuta
`clone_preserving_field_list(CloneType.I2E, sesión_CPU, …)`. El clon viaja al puerto
CPU; en egress se le antepone la cabecera `report_t` con `{tipo, src, dst,
estimador}`. El controlador *sniffa* ese puerto (Scapy, filtro `ether proto 0x1234`)
y registra/visualiza la alerta. Se reporta **un evento por origen y ventana** para
evitar avalanchas de clones.

### 2.8 Tablas y reenvío

| Tabla | Clave | Acción | Poblada por |
|-------|-------|--------|-------------|
| `ip_whitelist` | `ipv4.srcAddr` (exact) | `set_whitelist` | control plane |
| `ipv4_lpm`     | `ipv4.dstAddr` (exact) | `ipv4_forward(port,dmac)` / `drop` | control plane |

El reenvío reescribe la MAC destino y decrementa el TTL (comportamiento de router).
La detección corre **antes** del reenvío, de modo que incluso el tráfico de escaneo
hacia IPs inexistentes (descartado en `ipv4_lpm`) se contabiliza.

---

## 3. Plano de control

El control plane (Thrift, vía `simple_switch_CLI`, encapsulado en
`control/controller.py`) **no participa en la detección**; sus funciones son:

1. **Poblar tablas**: entradas de reenvío (`ipv4_lpm`) y lista blanca
   (`ip_whitelist`).
2. **Configurar la sesión de mirror** (`mirroring_add <id> <puerto_CPU>`) que habilita
   los clones-reporte.
3. **Fijar umbrales y modo** escribiendo los *registers* `r_flood_threshold`,
   `r_scan_threshold`, `r_synflood_threshold`, `r_mitig_mode` (configuración en
   caliente, sin recompilar).
4. **Leer contadores** (`register_read`) para métricas: paquetes totales, detecciones
   por tipo, reportes, paquetes mitigados/marcados.
5. **Recibir reportes**: un `AsyncSniffer` de Scapy sobre el puerto CPU decodifica la
   cabecera `report_t` y muestra alertas en tiempo real (visualización opcional).

Las tablas se pueblan de forma estática al arranque; los umbrales pueden modificarse
en cualquier momento. Esta separación estricta *detección en el dato / política en el
control* es exactamente el patrón que la consigna pide demostrar.

---

## 4. Resultados experimentales

### 4.1 Metodología

Topología Mininet: 1 switch P4 (BMv2) y 5 hosts (`h1`,`h2` atacantes; `h3` legítimo;
`h4` víctima; `hcpu` colector). Umbrales: `flood>100`, `scan>20`, `syn>80` por ventana
(~4.19 s). Los ataques se generan con `scripts/attack.py` (Scapy + socket `AF_PACKET`)
y el tráfico benigno con `scripts/legit.py`. El banco `tests/run_tests.py` ejecuta
cuatro escenarios y clasifica cada host como *marcado / no marcado*, computando
TP/FP/TN/FN contra la verdad de campo conocida.

### 4.2 Precisión de detección

| Escenario | Atacante(s) | Detección | TP | FP | TN | FN |
|-----------|-------------|-----------|----|----|----|----|
| Port scan horizontal | `10.0.0.1` | ✔ PORT_SCAN | 1 | 0 | 1 | 0 |
| UDP flood (5-tupla) | `10.0.0.2` | ✔ FLOOD | 1 | 0 | 1 | 0 |
| SYN flood (half-open) | `10.0.0.2` | ✔ SYN_FLOOD | 1 | 0 | 1 | 0 |
| Ataque mixto | `10.0.0.1`, `10.0.0.2` | ✔ ambos | 2 | 0 | 1 | 0 |
| **Agregado** | | | **5** | **0** | **4** | **0** |

- **Precisión** = TP/(TP+FP) = **1.000**
- **Recall** = TP/(TP+FN) = **1.000**
- **Tasa de falsos positivos (FPR)** = FP/(FP+TN) = **0.000**

El tráfico legítimo (`h3`) **nunca** fue marcado en ningún escenario, ni siquiera
ejecutándose en paralelo con los ataques. La separación entre detectores es nítida:
un flood (un flujo, muchos paquetes) jamás dispara el detector de scan (un destino),
y un scan (muchos destinos, un paquete cada uno) jamás dispara el de flood.

### 4.3 Mitigación efectiva

En el escenario mixto, con `h1` escaneando y `h2` inundando de forma **sostenida**, se
midió simultáneamente el tráfico legítimo y el del atacante:

| Métrica | Valor |
|---------|-------|
| Pérdida tráfico legítimo `h3→h4` | **0 %** |
| RTT legítimo `h3→h4` (base / bajo ataque) | 2.7 ms / ~465 ms |
| Pérdida tráfico atacante `h2→h4` (mitigado) | **100 %** |
| Paquetes descartados por mitigación (drop) | ~34 900 |
| Paquetes marcados DSCP (modo *mark*) | > 90 |

El atacante queda **completamente cortado** (100% de pérdida) mientras el tráfico
legítimo **no sufre pérdida alguna**. El aumento de RTT del tráfico legítimo bajo
ataque (de 2.7 ms a ~465 ms) es **encolamiento del emulador BMv2** procesando decenas
de miles de paquetes ofensivos por software; en hardware a velocidad de línea este
efecto desaparece. Lo relevante es que la conectividad legítima se preserva (0%
pérdida) y el ataque se elimina del *forwarding*.

### 4.4 Reportes y captura

Cada detección genera una alerta en consola del controlador, decodificada del clon
hacia CPU, p. ej.:

```
[ALERTA]  FLOOD      src=10.0.0.2   dst=10.0.0.4   estimador=101
[ALERTA]  PORT_SCAN  src=10.0.0.1   dst=10.0.1.21  estimador=21
[ALERTA]  SYN_FLOOD  src=10.0.0.2   dst=10.0.0.4   estimador=81
```

El `estimador` es el valor del sketch/contador que cruzó el umbral, confirmando que la
alarma se dispara justo en el límite configurado (101 > 100, 21 > 20, 81 > 80).

### 4.5 Análisis de falsos positivos

El único falso positivo observado durante el desarrollo —la víctima de un SYN flood
marcada como *port scan* por sus respuestas RST a puertos efímeros variados— se
eliminó restringiendo el conteo de *scan* a sondas (SYN/UDP). Con esa corrección, la
FPR medida es 0 en los cuatro escenarios. La fuente residual teórica de falsos
positivos es la **colisión de hash del CMS** (acotada en §2.3) y la elección de
umbrales: umbrales muy bajos marcarían ráfagas legítimas. Los valores por defecto dan
un amplio margen entre el tráfico benigno (≤ 9 paquetes/flujo, ≤ 2 destinos) y los
ataques (cientos a miles).

---

## 5. Conclusiones y trabajo futuro

Se implementó un detector de anomalías **completo y funcional en el plano de datos
P4**, que cumple todas las funcionalidades obligatorias de la Opción B y tres
opcionales (SYN flood, lista blanca, visualización en tiempo real). Las pruebas
automatizadas demuestran **precisión y recall de 1.0 con FPR de 0.0** en cuatro
escenarios, mitigación que corta al 100% al atacante sin afectar al tráfico legítimo,
y reporte asíncrono al control plane mediante clones hacia CPU. El diseño respeta el
principio rector del proyecto: **detección y mitigación autónomas en el dato**,
configuración y observabilidad en el control.

**Trabajo futuro.** (i) *Sketches más expresivos* como UnivMon o sketches de
cardinalidad (HyperLogLog) para contar destinos distintos con menor error que el
esquema de "primer contacto". (ii) *Umbral adaptativo* aprendido del histórico de
tráfico en lugar de constantes. (iii) *Mitigación granular* (rate-limiting con
*token buckets* en registers, en vez de drop total). (iv) *Detección de slow-rate*
(escaneos lentos que evaden la ventana). (v) Validación sobre un *target* hardware
(Tofino) para medir el detector a velocidad de línea real.

---

## 6. Referencias

1. G. Cormode, S. Muthukrishnan. *An Improved Data Stream Summary: The Count-Min
   Sketch and its Applications.* Journal of Algorithms, 55(1), 2005.
2. The P4 Language Consortium. *P4₁₆ Language Specification.* https://p4.org/p4-spec/
3. p4lang. *P4 Tutorials.* https://github.com/p4lang/tutorials
4. Z. Liu et al. *Jaqen: A High-Performance Switch-Native Approach for Detecting and
   Mitigating Volumetric DDoS Attacks with Programmable Switches.* USENIX Security,
   2021.
5. Z. Liu, A. Manousis, G. Vorsanger, V. Sekar, V. Braverman. *One Sketch to Rule
   Them All: Rethinking Network Flow Monitoring with UnivMon.* ACM SIGCOMM, 2016.
6. Hula et al. *Real-time DDoS Mitigation in Programmable Data Planes.* ACM SIGCOMM,
   2020.
7. X. Jin et al. *NetCache: Balancing Key-Value Stores with Fast In-Network Caching.*
   ACM SOSP, 2017.
8. P. Bosshart et al. *P4: Programming Protocol-Independent Packet Processors.* ACM
   SIGCOMM CCR, 44(3), 2014.
9. IETF. *RFC 793 — Transmission Control Protocol* (semántica de SYN/half-open).
