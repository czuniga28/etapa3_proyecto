/* -*- P4_16 -*- */
/*
 * anomaly.p4 — Detección de Anomalías de Tráfico en el Data Plane (BMv2 / v1model)
 *
 * Proyecto Final de Redes Programables con P4 — Opción B.
 *
 * El switch analiza el tráfico en tiempo real (sin intervención del control plane
 * para detectar/mitigar) y reconoce tres clases de anomalías:
 *
 *   1. PORT SCAN HORIZONTAL  — misma IP origen contactando muchas parejas
 *                              (IP destino, puerto destino) distintas en una ventana.
 *   2. FLOOD (pps)           — un flujo individual (5-tupla) que supera un umbral
 *                              de paquetes por ventana (≈ paquetes por segundo).
 *   3. SYN FLOOD (opcional)  — exceso de SYN TCP hacia una misma víctima
 *                              (aproximación de conexiones half-open).
 *
 * Estructuras de datos en el data plane:
 *   - Count-Min Sketch (CMS) de d=3 filas x w=4096 columnas, con ventana temporal
 *     (cada celda guarda su época; al cambiar de época la celda se reinicia de forma
 *     perezosa). El estimador de frecuencia de un flujo es el mínimo de las 3 filas.
 *   - Sketch de "primer contacto" para contar destinos distintos por origen (port scan).
 *   - Registros de mitigación (blocklist) por origen, con época, poblados por el
 *     propio data plane.
 *
 * Acciones de mitigación (configurables vía registro mitig_mode):
 *   - mode 0: DROP de los paquetes del origen marcado.
 *   - mode 1: MARK del campo DSCP (diffserv) de los paquetes sospechosos.
 *
 * Reporte al control plane: clone I2E del primer paquete que dispara cada anomalía
 * hacia el puerto CPU, anteponiendo un encabezado report_t (tipo, src, dst, estimador).
 *
 * Las funcionalidades opcionales implementadas: SYN flood, lista blanca (whitelist),
 * y visualización en consola (en el controlador Python).
 */

#include <core.p4>
#include <v1model.p4>

/*************************************************************************
 ***********************  C O N S T A N T S  *****************************
 *************************************************************************/

const bit<16> TYPE_IPV4   = 0x0800;
const bit<16> TYPE_REPORT = 0x1234;   // EtherType propietario para clones-reporte
const bit<8>  PROTO_TCP   = 6;
const bit<8>  PROTO_UDP   = 17;

/* Count-Min Sketch: d filas x w columnas. */
#define CMS_W 4096           // columnas por fila (potencia de 2)
const bit<32> CMS_WIDTH = 4096;

/* Ventana temporal: la época es el timestamp (us) desplazado WINDOW_SHIFT bits.
 * 2^22 us ≈ 4.19 s por ventana. Los umbrales se expresan por ventana; el umbral
 * de pps efectivo es (umbral / duración_ventana). Una ventana de varios segundos
 * da robustez frente a la baja tasa de procesamiento de BMv2 bajo emulación. */
#define WINDOW_SHIFT 22

/* Sales para decorrelacionar las 3 filas del CMS (mismo algoritmo crc32). */
const bit<16> SALT0 = 0x0000;
const bit<16> SALT1 = 0x5a5a;
const bit<16> SALT2 = 0xa5a5;

/* Tipos de anomalía (en el report header y contadores). */
const bit<8> ANOM_PORTSCAN = 1;
const bit<8> ANOM_FLOOD    = 2;
const bit<8> ANOM_SYNFLOOD = 3;

/* Instance type de un paquete clonado I2E en BMv2 (PKT_INSTANCE_TYPE_INGRESS_CLONE). */
const bit<32> PKT_INSTANCE_TYPE_INGRESS_CLONE = 1;

/* Sesión de mirror (clone) hacia el puerto CPU; la configura el control plane. */
const bit<32> CPU_MIRROR_SESSION = 100;

/* Valor DSCP usado al marcar tráfico sospechoso (diffserv = DSCP<<2 | ECN). */
const bit<8> DSCP_SUSPECT = 0xB8;   // DSCP 46 (EF) << 2

/*************************************************************************
 *********************  H E A D E R S  ***********************************
 *************************************************************************/

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/* Encabezado de reporte que se antepone únicamente en los clones hacia CPU. */
header report_t {
    bit<8>  anomaly_type;   // 1=portscan, 2=flood, 3=synflood
    bit<32> src;            // IP origen ofensora
    bit<32> dst;            // IP destino observada
    bit<32> estimate;       // valor estimado (CMS / contador) que disparó la alarma
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;          // CWR ECE URG ACK PSH RST SYN FIN
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct headers {
    ethernet_t ethernet;
    report_t   report;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

/*************************************************************************
 *********************  M E T A D A T A  *********************************
 *************************************************************************/

struct metadata {
    bit<16> l4_src;
    bit<16> l4_dst;
    bit<1>  is_syn;          // SYN puesto y ACK no puesto
    bit<32> cur_epoch;

    /* índices del sketch */
    bit<32> idx0;
    bit<32> idx1;
    bit<32> idx2;
    bit<32> seen_idx;
    bit<32> src_idx;
    bit<32> dst_idx;
    bit<32> blk_idx;

    bit<32> flow_est;        // estimador CMS de la 5-tupla
    bit<32> scan_est;        // contador de destinos distintos por origen
    bit<32> syn_est;         // contador de SYN por destino

    bit<1>  whitelisted;
    bit<1>  is_portscan;
    bit<1>  is_flood;
    bit<1>  is_synflood;
    bit<1>  anomaly;
    bit<1>  blocked;
    bit<1>  do_report;

    /* campos preservados hacia egress en el clone (no viajan en el paquete) */
    @field_list(1) bit<8>  report_type;
    @field_list(1) bit<32> report_est;
}

/*************************************************************************
 *********************  P A R S E R  *************************************
 *************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default:   accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*************************************************************************
 ***************  C H E C K S U M   V E R I F Y  *************************
 *************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ********************  I N G R E S S  ************************************
 *************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* ---------- Count-Min Sketch (flood por 5-tupla, con ventana) ---------- */
    register<bit<32>>(CMS_WIDTH) cms_count0;
    register<bit<32>>(CMS_WIDTH) cms_count1;
    register<bit<32>>(CMS_WIDTH) cms_count2;
    register<bit<32>>(CMS_WIDTH) cms_epoch0;
    register<bit<32>>(CMS_WIDTH) cms_epoch1;
    register<bit<32>>(CMS_WIDTH) cms_epoch2;

    /* ---------- Sketch de "primer contacto" para port scan ---------- */
    register<bit<32>>(CMS_WIDTH) seen_epoch;   // época del último (src,dst,dport) visto
    register<bit<32>>(CMS_WIDTH) scan_count;   // destinos distintos por origen (ventana)
    register<bit<32>>(CMS_WIDTH) scan_epoch;

    /* ---------- Contador de SYN por destino (SYN flood) ---------- */
    register<bit<32>>(CMS_WIDTH) syn_count;
    register<bit<32>>(CMS_WIDTH) syn_epoch;

    /* ---------- Blocklist de mitigación por origen ---------- */
    register<bit<32>>(CMS_WIDTH) blk_val;      // 1 = origen bloqueado en esta ventana
    register<bit<32>>(CMS_WIDTH) blk_epoch;

    /* ---------- Umbrales y modo, configurables por el control plane ---------- */
    register<bit<32>>(1) r_flood_threshold;
    register<bit<32>>(1) r_scan_threshold;
    register<bit<32>>(1) r_synflood_threshold;
    register<bit<32>>(1) r_mitig_mode;         // 0=drop, 1=mark DSCP

    /* ---------- Contadores legibles desde el controlador ---------- */
    register<bit<32>>(1) c_total;
    register<bit<32>>(1) c_portscan;
    register<bit<32>>(1) c_flood;
    register<bit<32>>(1) c_synflood;
    register<bit<32>>(1) c_reports;
    register<bit<32>>(1) c_mitigated;          // paquetes drop por mitigación
    register<bit<32>>(1) c_marked;             // paquetes marcados (DSCP)

    /* --------------------------- Acciones --------------------------- */

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_whitelist() {
        meta.whitelisted = 1;
    }

    action ipv4_forward(bit<9> port, bit<48> dstMac) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* Lista blanca de IPs inmunes a la detección (opcional). */
    table ip_whitelist {
        key = { hdr.ipv4.srcAddr: exact; }
        actions = { set_whitelist; NoAction; }
        size = 64;
        default_action = NoAction();
    }

    /* Reenvío por IP destino (poblada por el controlador). */
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    /* ----------------------------- Pipeline ----------------------------- */
    apply {
        if (!hdr.ipv4.isValid()) {
            return;   // sólo se procesa IPv4
        }

        /* contador total */
        bit<32> tot;
        c_total.read(tot, 0);
        c_total.write(0, tot + 1);

        /* época actual de la ventana temporal */
        meta.cur_epoch = (bit<32>)(standard_metadata.ingress_global_timestamp >> WINDOW_SHIFT);

        /* puertos L4 y bandera SYN */
        meta.l4_src = 0;
        meta.l4_dst = 0;
        meta.is_syn = 0;
        if (hdr.tcp.isValid()) {
            meta.l4_src = hdr.tcp.srcPort;
            meta.l4_dst = hdr.tcp.dstPort;
            /* SYN=bit1, ACK=bit4 -> SYN set & ACK not set */
            if ((hdr.tcp.flags & 0x02) != 0 && (hdr.tcp.flags & 0x10) == 0) {
                meta.is_syn = 1;
            }
        } else if (hdr.udp.isValid()) {
            meta.l4_src = hdr.udp.srcPort;
            meta.l4_dst = hdr.udp.dstPort;
        }

        /* leer umbrales */
        bit<32> th_flood; bit<32> th_scan; bit<32> th_syn; bit<32> mode;
        r_flood_threshold.read(th_flood, 0);
        r_scan_threshold.read(th_scan, 0);
        r_synflood_threshold.read(th_syn, 0);
        r_mitig_mode.read(mode, 0);

        /* lista blanca */
        ip_whitelist.apply();

        if (meta.whitelisted == 0) {
            /* ============ CMS: estimar frecuencia de la 5-tupla ============ */
            hash(meta.idx0, HashAlgorithm.crc32, (bit<32>)0,
                 { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, meta.l4_src, meta.l4_dst,
                   hdr.ipv4.protocol, SALT0 }, CMS_WIDTH);
            hash(meta.idx1, HashAlgorithm.crc32, (bit<32>)0,
                 { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, meta.l4_src, meta.l4_dst,
                   hdr.ipv4.protocol, SALT1 }, CMS_WIDTH);
            hash(meta.idx2, HashAlgorithm.crc32, (bit<32>)0,
                 { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, meta.l4_src, meta.l4_dst,
                   hdr.ipv4.protocol, SALT2 }, CMS_WIDTH);

            bit<32> c0; bit<32> c1; bit<32> c2;
            bit<32> e0; bit<32> e1; bit<32> e2;

            cms_epoch0.read(e0, meta.idx0); cms_count0.read(c0, meta.idx0);
            if (e0 != meta.cur_epoch) { c0 = 1; cms_epoch0.write(meta.idx0, meta.cur_epoch); }
            else { c0 = c0 + 1; }
            cms_count0.write(meta.idx0, c0);

            cms_epoch1.read(e1, meta.idx1); cms_count1.read(c1, meta.idx1);
            if (e1 != meta.cur_epoch) { c1 = 1; cms_epoch1.write(meta.idx1, meta.cur_epoch); }
            else { c1 = c1 + 1; }
            cms_count1.write(meta.idx1, c1);

            cms_epoch2.read(e2, meta.idx2); cms_count2.read(c2, meta.idx2);
            if (e2 != meta.cur_epoch) { c2 = 1; cms_epoch2.write(meta.idx2, meta.cur_epoch); }
            else { c2 = c2 + 1; }
            cms_count2.write(meta.idx2, c2);

            /* estimador = mínimo de las 3 filas */
            meta.flow_est = c0;
            if (c1 < meta.flow_est) { meta.flow_est = c1; }
            if (c2 < meta.flow_est) { meta.flow_est = c2; }

            if (meta.flow_est > th_flood) {
                meta.is_flood = 1;
            }

            /* ============ Port scan: contar destinos distintos por origen ============ */
            /* Sólo se consideran "sondas" de escaneo los SYN TCP y los paquetes
             * UDP; así las respuestas TCP de una víctima (RST/ACK hacia puertos
             * efímeros variados) no se confunden con un escaneo horizontal. */
            bool scan_probe = (meta.is_syn == 1) || hdr.udp.isValid();
            if (scan_probe) {
            /* "primer contacto" de (src,dst,dport) en la ventana */
            hash(meta.seen_idx, HashAlgorithm.crc32, (bit<32>)0,
                 { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, meta.l4_dst, hdr.ipv4.protocol },
                 CMS_WIDTH);
            bit<32> se;
            seen_epoch.read(se, meta.seen_idx);
            bit<1> new_contact = 0;
            if (se != meta.cur_epoch) {
                new_contact = 1;
                seen_epoch.write(meta.seen_idx, meta.cur_epoch);
            }

            if (new_contact == 1) {
                hash(meta.src_idx, HashAlgorithm.crc32, (bit<32>)0,
                     { hdr.ipv4.srcAddr, SALT1 }, CMS_WIDTH);
                bit<32> sc; bit<32> sce;
                scan_epoch.read(sce, meta.src_idx); scan_count.read(sc, meta.src_idx);
                if (sce != meta.cur_epoch) { sc = 1; scan_epoch.write(meta.src_idx, meta.cur_epoch); }
                else { sc = sc + 1; }
                scan_count.write(meta.src_idx, sc);
                meta.scan_est = sc;
                if (sc > th_scan) {
                    meta.is_portscan = 1;
                }
            }
            }  /* fin if(scan_probe) */

            /* ============ SYN flood: SYN por par (origen,víctima) en la ventana ====
             * Se cuenta por (src,dst) — agregando todos los puertos origen — para
             * (a) detectar la avalancha de SYN que el CMS por 5-tupla no ve, y
             * (b) atribuir correctamente el origen ofensor (no la víctima). */
            if (meta.is_syn == 1) {
                hash(meta.dst_idx, HashAlgorithm.crc32, (bit<32>)0,
                     { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, SALT2 }, CMS_WIDTH);
                bit<32> sy; bit<32> sye;
                syn_epoch.read(sye, meta.dst_idx); syn_count.read(sy, meta.dst_idx);
                if (sye != meta.cur_epoch) { sy = 1; syn_epoch.write(meta.dst_idx, meta.cur_epoch); }
                else { sy = sy + 1; }
                syn_count.write(meta.dst_idx, sy);
                meta.syn_est = sy;
                if (sy > th_syn) {
                    meta.is_synflood = 1;
                }
            }

            /* ============ Consolidación y blocklist ============ */
            meta.anomaly = meta.is_portscan | meta.is_flood | meta.is_synflood;

            hash(meta.blk_idx, HashAlgorithm.crc32, (bit<32>)0,
                 { hdr.ipv4.srcAddr, SALT0 }, CMS_WIDTH);
            bit<32> bv; bit<32> be;
            blk_epoch.read(be, meta.blk_idx); blk_val.read(bv, meta.blk_idx);
            if (be != meta.cur_epoch) { bv = 0; }   // reinicio perezoso por ventana
            bit<32> bv_before = bv;
            if (meta.anomaly == 1) { bv = 1; }
            if (be != meta.cur_epoch || meta.anomaly == 1) {
                blk_epoch.write(meta.blk_idx, meta.cur_epoch);
            }
            blk_val.write(meta.blk_idx, bv);
            meta.blocked = (bit<1>)bv;

            /* reportar sólo en el primer paquete que dispara la anomalía en la ventana */
            if (meta.anomaly == 1 && bv_before == 0) {
                meta.do_report = 1;
            }

            /* tipo de anomalía dominante para el reporte / contadores */
            if (meta.is_flood == 1) {
                meta.report_type = ANOM_FLOOD;
                meta.report_est  = meta.flow_est;
            } else if (meta.is_portscan == 1) {
                meta.report_type = ANOM_PORTSCAN;
                meta.report_est  = meta.scan_est;
            } else if (meta.is_synflood == 1) {
                meta.report_type = ANOM_SYNFLOOD;
                meta.report_est  = meta.syn_est;
            }

            /* contadores por tipo (a nivel de paquete detectado) */
            if (meta.is_portscan == 1) { bit<32> v; c_portscan.read(v,0); c_portscan.write(0,v+1); }
            if (meta.is_flood == 1)    { bit<32> v; c_flood.read(v,0);    c_flood.write(0,v+1); }
            if (meta.is_synflood == 1) { bit<32> v; c_synflood.read(v,0); c_synflood.write(0,v+1); }
        }

        /* ============ Reporte al control plane (clone hacia CPU) ============ */
        if (meta.do_report == 1) {
            bit<32> r; c_reports.read(r,0); c_reports.write(0, r+1);
            clone_preserving_field_list(CloneType.I2E, CPU_MIRROR_SESSION, (bit<8>)1);
        }

        /* ============ Reenvío + mitigación ============ */
        ipv4_lpm.apply();

        if (meta.blocked == 1) {
            if (mode == 0) {
                /* modo DROP */
                bit<32> m; c_mitigated.read(m,0); c_mitigated.write(0, m+1);
                drop();
            } else {
                /* modo MARK: marcar DSCP y dejar pasar */
                hdr.ipv4.diffserv = DSCP_SUSPECT;
                bit<32> m; c_marked.read(m,0); c_marked.write(0, m+1);
            }
        }
    }
}

/*************************************************************************
 ********************  E G R E S S  *************************************
 *************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        /* Para el paquete clonado hacia CPU, anteponer el report header. */
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE) {
            hdr.report.setValid();
            hdr.report.anomaly_type = meta.report_type;
            hdr.report.src          = hdr.ipv4.srcAddr;
            hdr.report.dst          = hdr.ipv4.dstAddr;
            hdr.report.estimate     = meta.report_est;
            hdr.ethernet.etherType  = TYPE_REPORT;
        }
    }
}

/*************************************************************************
 *************  C H E C K S U M   C O M P U T A T I O N  ****************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
 ***********************  D E P A R S E R  ******************************
 *************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.report);   // sólo válido en clones hacia CPU
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
 ***************************  S W I T C H  ******************************
 *************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
