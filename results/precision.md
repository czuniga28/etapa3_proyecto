# Análisis de Precisión de Detección

Umbrales: flood>100 pkt/ventana, scan>20 dest/ventana, syn>80/ventana (ventana ≈ 4.19 s = 2^22 us).

| Escenario | Atacantes | Detecciones (pkt) | TP | FP | TN | FN |
|-----------|-----------|-------------------|----|----|----|----|
| Port scan horizontal | 10.0.0.1 | 17 | 1 | 0 | 1 | 0 |
| UDP flood (5-tupla) | 10.0.0.2 | 27572 | 1 | 0 | 1 | 0 |
| SYN flood (half-open) | 10.0.0.2 | 24172 | 1 | 0 | 1 | 0 |
| Ataque mixto + mitigación | 10.0.0.1,10.0.0.2 | — | 2 | 0 | 1 | 0 |

**Agregado:** TP=5, FP=0, TN=4, FN=0

- Precisión = 1.000
- Recall (sensibilidad) = 1.000
- Tasa de falsos positivos (FPR) = 0.000

## Mitigación (Escenario 4 — ataque mixto)

| Métrica | Valor |
|---------|-------|
| Pérdida tráfico legítimo h3→h4 | 0% |
| RTT legítimo h3→h4 durante ataque | 454.823 ms |
| Pérdida tráfico atacante h2→h4 (mitigado) | 100% |
| Paquetes descartados por mitigación | 36184 |
| Paquetes marcados DSCP (modo mark) | 162 |

RTT legítimo base (sin ataque): 2.48 ms; pérdida base: 0%.
