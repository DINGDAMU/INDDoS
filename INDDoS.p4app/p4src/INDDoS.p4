#include <core.p4>
#include <v1model.p4>

#define MAX_DDoS_SIZE 131072
#define DDoS_threshold 200

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
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
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}

struct metadata {
    bit<32> count_min;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
    @name(".udp") 
    udp_t      udp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            8w0x11: parse_udp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".rewrite_mac") action rewrite_mac(bit<48> smac) {
        hdr.ethernet.srcAddr = smac;
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name(".send_frame") table send_frame {
        actions = {
            rewrite_mac;
            _drop;
        }
        key = {
            standard_metadata.egress_port: exact;
        }
        size = 256;
    }
    apply {
        send_frame.apply();
    }
}

register<bit<32>>(1024) occSlots1;
register<bit<32>>(1024) occSlots2;
register<bit<32>>(1024) occSlots3;

register<bit<1>>(MAX_DDoS_SIZE) cms1_0;
register<bit<1>>(MAX_DDoS_SIZE) cms1_1;
register<bit<1>>(MAX_DDoS_SIZE) cms1_2;
register<bit<1>>(MAX_DDoS_SIZE) cms1_3;
register<bit<1>>(MAX_DDoS_SIZE) cms1_4;
register<bit<1>>(MAX_DDoS_SIZE) cms1_5;
register<bit<1>>(MAX_DDoS_SIZE) cms1_6;
register<bit<1>>(MAX_DDoS_SIZE) cms1_7;

register<bit<1>>(MAX_DDoS_SIZE) cms2_0;
register<bit<1>>(MAX_DDoS_SIZE) cms2_1;
register<bit<1>>(MAX_DDoS_SIZE) cms2_2;
register<bit<1>>(MAX_DDoS_SIZE) cms2_3;
register<bit<1>>(MAX_DDoS_SIZE) cms2_4;
register<bit<1>>(MAX_DDoS_SIZE) cms2_5;
register<bit<1>>(MAX_DDoS_SIZE) cms2_6;
register<bit<1>>(MAX_DDoS_SIZE) cms2_7;

register<bit<1>>(MAX_DDoS_SIZE) cms3_0;
register<bit<1>>(MAX_DDoS_SIZE) cms3_1;
register<bit<1>>(MAX_DDoS_SIZE) cms3_2;
register<bit<1>>(MAX_DDoS_SIZE) cms3_3;
register<bit<1>>(MAX_DDoS_SIZE) cms3_4;
register<bit<1>>(MAX_DDoS_SIZE) cms3_5;
register<bit<1>>(MAX_DDoS_SIZE) cms3_6;
register<bit<1>>(MAX_DDoS_SIZE) cms3_7;
control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action ipv4_forward(bit<48> dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 8w1;
    }
    action _drop() {
        mark_to_drop();
    }

    table ipv4_lpm {
        actions = {
            ipv4_forward;
            _drop;
        }
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        size = 1024;
    }
    apply {
        ipv4_lpm.apply();
        // Index in Count-min sketch (Size 1024)
        bit<10> hash_32_1;
        bit<10> hash_32_2;
        bit<10> hash_32_3;
        // Index in Bitmap (Size 1024)
        bit<10> bm_hash;
        // Index in BACON Sketch (Size 1024 * 1024)
        bit<32> index1 = 32w0;
        bit<32> index2 = 32w0;
        bit<32> index3 = 32w0;
        // Values in BACON Sketch (0 or 1)
        bit<1> res1 = 1w0;
        bit<1> res2 = 1w0;
        bit<1> res3 = 1w0;
        // Number of 1s in BACON Sketch
        bit<32> value_1 = 32w0;
        bit<32> value_2 = 32w0;
        bit<32> value_3 =32w0;

        // Difference between values
        bit<32> d12;
        bit<32> d13;
        bit<32> d23;

        // Digest
        // 0: No report
        // 1: Report hdr.ipv4.dstAddr to controller
        bit<1> digest_type;

        //crc32_custom: 
        // Please refer to the paer how to customize CRC32
        hash(hash_32_1, HashAlgorithm.crc32, 1w0, {hdr.ipv4.dstAddr}, 10w1023);
        hash(hash_32_2, HashAlgorithm.crc32_custom, 1w0, {hdr.ipv4.dstAddr}, 10w1023);
        hash(hash_32_3, HashAlgorithm.crc32_custom, 1w0, {hdr.ipv4.dstAddr}, 10w1023);
        hash(bm_hash, HashAlgorithm.crc32, 1w0, {hdr.ipv4.srcAddr}, 10w1023);
        
        index1[9:0] = bm_hash;
        index2[9:0] = bm_hash;
        index2[9:0] = bm_hash;

        index1[16:10] = hash_32_1[6:0];
        index2[16:10] = hash_32_2[6:0];
        index3[16:10] = hash_32_3[6:0];

        if(hash_32_1[9:7] == 0){
             cms1_0.read(res1, index1);
             if(res1==0){
             cms1_0.write(index1, 1);
             }
        }else if(hash_32_1[9:7] == 1){
             cms1_1.read(res1, index1);
             if(res1==0){
             cms1_1.write(index1, 1);
             }
        }else if(hash_32_1[9:7] == 2){
             cms1_2.read(res1, index1);
             if(res1==0){
             cms1_2.write(index1, 1);
             }
        }else if(hash_32_1[9:7] == 3){
             cms1_3.read(res1, index1);
             if(res1==0){
             cms1_3.write(index1, 1);
             }
        }else if(hash_32_1[9:7] == 4){
             cms1_4.read(res1, index1);
             if(res1==0){
             cms1_4.write(index1, 1);
             }
        }else if(hash_32_1[9:7] == 5){
             cms1_5.read(res1, index1);
             if(res1==0){
             cms1_5.write(index1, 1);
             }
        }else if(hash_32_1[9:7] == 6){
             cms1_6.read(res1, index1);
             if(res1==0){
             cms1_6.write(index1, 1);
             }
        }else if(hash_32_1[9:7] == 7){
             cms1_7.read(res1, index1);
             if(res1==0){
             cms1_7.write(index1, 1);
             }
        }

        if(hash_32_2[9:7] == 0){
             cms2_0.read(res2, index2);
             if(res2==0){
             cms2_0.write(index2, 1);
             }
        }else if(hash_32_2[9:7] == 1){
             cms2_1.read(res2, index2);
             if(res2==0){
             cms2_1.write(index2, 1);
             }
        }else if(hash_32_2[9:7] == 2){
             cms2_2.read(res2, index2);
             if(res2==0){
             cms2_2.write(index2, 1);
             }
        }else if(hash_32_2[9:7] == 3){
             cms2_3.read(res2, index2);
             if(res2==0){
             cms2_3.write(index2, 1);
             }
        }else if(hash_32_2[9:7] == 4){
             cms2_4.read(res2, index2);
             if(res2==0){
             cms2_4.write(index2, 1);
             }
        }else if(hash_32_2[9:7] == 5){
             cms2_5.read(res2, index2);
             if(res2==0){
             cms2_5.write(index2, 1);
             }
        }else if(hash_32_2[9:7] == 6){
             cms2_6.read(res2, index2);
             if(res2==0){
             cms2_6.write(index2, 1);
             }
        }else if(hash_32_2[9:7] == 7){
             cms2_7.read(res2, index2);
             if(res2==0){
             cms2_7.write(index2, 1);
             }
        }

        if(hash_32_3[9:7] == 0){
             cms3_0.read(res3, index3);
             if(res3==0){
             cms3_0.write(index3, 1);
             }
        }else if(hash_32_3[9:7] == 1){
             cms3_1.read(res3, index3);
             if(res3==0){
             cms3_1.write(index3, 1);
             }
        }else if(hash_32_3[9:7] == 2){
             cms3_2.read(res3, index3);
             if(res3==0){
             cms3_2.write(index3, 1);
             }
        }else if(hash_32_3[9:7] == 3){
             cms3_3.read(res3, index3);
             if(res3==0){
             cms3_3.write(index3, 1);
             }
        }else if(hash_32_3[9:7] == 4){
             cms3_4.read(res3, index3);
             if(res3==0){
             cms3_4.write(index3, 1);
             }
        }else if(hash_32_3[9:7] == 5){
             cms3_5.read(res3, index3);
             if(res3==0){
             cms3_5.write(index3, 1);
             }
        }else if(hash_32_3[9:7] == 6){
             cms3_6.read(res3, index3);
             if(res3==0){
             cms3_6.write(index3, 1);
             }
        }else if(hash_32_3[9:7] == 7){
             cms3_7.read(res3, index3);
             if(res3==0){
             cms3_7.write(index3, 1);
             }
        }
        if(res1 == 0){
            occSlots1.read(value_1, (bit<32>)hash_32_1);
            value_1 = value_1 + 1;
            occSlots1.write((bit<32>)hash_32_1, value_1);
        }

        if(res2 == 0){
            occSlots2.read(value_2, (bit<32>)hash_32_2);
            value_2 = value_2 + 1;
            occSlots2.write((bit<32>)hash_32_2, value_2);
        }

        if(res3 == 0){
            occSlots3.read(value_3, (bit<32>)hash_32_3);
            value_3 = value_3 + 1;
            occSlots3.write((bit<32>)hash_32_3, value_3);
        }

        d12 = value_1 - value_2;
        d13 = value_1 - value_3;
        d23 = value_2 - value_3;
        if (d12 < 0 && d13 < 0){
            meta.count_min = value_1;
        }else if (d12 > 0 && d23 <0){
            meta.count_min = value_2;
        }else{
            meta.count_min = value_3;
        }

        if (meta.count_min == DDoS_threshold + 1){
            digest_type = 1;
        }

    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

