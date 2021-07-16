/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
 **************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;

/* Table Sizes */
const int<32> IPV4_HOST_SIZE = 65536;
const int IPV4_LPM_SIZE  = 12288;
const bit<32> MAX_SIZE = 1024; // Bitmap size
const bit<32> MAX_BH = 9;// MAX_BH = log2(MAX_SIZE)-1
const bit<32> MAX_BH_begin = 10;// MAX_BH_begin = MAX_BH + 1
const bit<32> MAX_CMS_SIZE = 1024; //CMS_SIZE
const bit<32> MAX_DDoS_SIZE = 131072; // The max size of register is 131072
const bit<32> MAX_H = 9;// MAX_H = log2(MAX_CMS_SIZE)-1
const bit<32> MAX_H_min = 7;// MAX_H = MAX_H - 2 (log2(1024*1024) - log2(131072)) Fixed
const bit<32> MAX_H_begin = 10;// MAX_H = log2(MAX_CMS_SIZE)
const bit<32> MAX_end = 19;// log2(MAX_DDoS_SIZE) - 1
const bit<32> UP = 16; // MAX_BH_begin + 6
const bit<32> DDoS_threshold = 239; // Define the threshold here

/* Typedef*/
typedef bit<32> data_t;
typedef bit<1> bit_t;
typedef bit<(MAX_H_begin)> hash_t;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}



/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
/***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
}

/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<1> res_1;
    bit<1> res_2;
    bit<1> res_3;
    bit<32> count_min;
}


/******  DIGEST  *********/

struct digest_t{
    data_t  dst_addr;
}
/***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }
    //Remove since CAIDA trace does not have Ethernet header
      state parse_ethernet {
    pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.ether_type) {
    ETHERTYPE_TPID:  parse_vlan_tag;
    ETHERTYPE_IPV4:  parse_ipv4;
    default: accept;
    }
    }

    state parse_vlan_tag {
    pkt.extract(hdr.vlan_tag);
    transition select(hdr.vlan_tag.ether_type) {
    ETHERTYPE_IPV4:  parse_ipv4;
    default: accept;
    }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }

}

/***************** M A T C H - A C T I O N  *********************/
control cal_ipv4_hash(in my_ingress_headers_t hdr, out hash_t hash)(bit<32> coeff)
{

    CRCPolynomial<bit<32>>(
        coeff, 
        true,
        false,
        false,
        0xFFFFFFFF,
        0xFFFFFFFF) poly;


    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;


    action do_hash(){
        hash = (hash_algo.get({
                hdr.ipv4.dst_addr
                })[MAX_H:0]);
    }
    apply{
        do_hash();
    }
}
control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms1_0;
    RegisterAction<bit_t, data_t, bit_t>(cms1_0)
        update_cms1_0 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms1_1;
    RegisterAction<bit_t, data_t, bit_t>(cms1_1)
        update_cms1_1 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms1_2;
    RegisterAction<bit_t, data_t, bit_t>(cms1_2)
        update_cms1_2 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms1_3;
    RegisterAction<bit_t, data_t, bit_t>(cms1_3)
        update_cms1_3 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms1_4;
    RegisterAction<bit_t, data_t, bit_t>(cms1_4)
        update_cms1_4 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms1_5;
    RegisterAction<bit_t, data_t, bit_t>(cms1_5)
        update_cms1_5 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms1_6;
    RegisterAction<bit_t, data_t, bit_t>(cms1_6)
        update_cms1_6 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms1_7;
    RegisterAction<bit_t, data_t, bit_t>(cms1_7)
        update_cms1_7 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

     Register<bit_t, data_t>(MAX_DDoS_SIZE) cms2_0;
    RegisterAction<bit_t, data_t, bit_t>(cms2_0)
        update_cms2_0 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms2_1;
    RegisterAction<bit_t, data_t, bit_t>(cms2_1)
        update_cms2_1 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms2_2;
    RegisterAction<bit_t, data_t, bit_t>(cms2_2)
        update_cms2_2 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms2_3;
    RegisterAction<bit_t, data_t, bit_t>(cms2_3)
        update_cms2_3 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms2_4;
    RegisterAction<bit_t, data_t, bit_t>(cms2_4)
        update_cms2_4 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms2_5;
    RegisterAction<bit_t, data_t, bit_t>(cms2_5)
        update_cms2_5 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms2_6;
    RegisterAction<bit_t, data_t, bit_t>(cms2_6)
        update_cms2_6 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms2_7;
    RegisterAction<bit_t, data_t, bit_t>(cms2_7)
        update_cms2_7 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

  

   Register<bit_t, data_t>(MAX_DDoS_SIZE) cms3_0;
    RegisterAction<bit_t, data_t, bit_t>(cms3_0)
        update_cms3_0 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms3_1;
    RegisterAction<bit_t, data_t, bit_t>(cms3_1)
        update_cms3_1 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms3_2;
    RegisterAction<bit_t, data_t, bit_t>(cms3_2)
        update_cms3_2 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms3_3;
    RegisterAction<bit_t, data_t, bit_t>(cms3_3)
        update_cms3_3 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms3_4;
    RegisterAction<bit_t, data_t, bit_t>(cms3_4)
        update_cms3_4 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms3_5;
    RegisterAction<bit_t, data_t, bit_t>(cms3_5)
        update_cms3_5 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms3_6;
    RegisterAction<bit_t, data_t, bit_t>(cms3_6)
        update_cms3_6 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };

    Register<bit_t, data_t>(MAX_DDoS_SIZE) cms3_7;
    RegisterAction<bit_t, data_t, bit_t>(cms3_7)
        update_cms3_7 = {
            void apply(inout bit_t value, out bit_t result) {
                result = ~value;
                value = 1;
            }
        };


    
    Register<data_t, data_t>(MAX_CMS_SIZE) occSlots1;
    RegisterAction<data_t, data_t, data_t>(occSlots1)
        update_occ1 = {
            void apply(inout data_t value, out data_t result) {
                if (meta.res_1 == 1){
                    value = value + 1;
                }
                result = value;
            }
        };

    Register<data_t, data_t>(MAX_CMS_SIZE) occSlots2;
    RegisterAction<data_t, data_t, data_t>(occSlots2)
        update_occ2 = {
            void apply(inout data_t value, out data_t result) {
                if (meta.res_2 == 1){
                    value = value + 1;
                }

                result = value;
            }
        };

    Register<data_t, data_t>(MAX_CMS_SIZE) occSlots3;
    RegisterAction<data_t, data_t, data_t>(occSlots3)
        update_occ3 = {
            void apply(inout data_t value, out data_t result) {
                if (meta.res_3 == 1){
                    value = value + 1;
                }
                result = value;
            }
        };


    Register<data_t, data_t>(1) intimeReg;
    RegisterAction<data_t, data_t, data_t>(intimeReg)
        update_intimeReg = {
            void apply(inout data_t value) {
                value = (bit<32>)ig_prsr_md.global_tstamp;
            }
        };

    /*Hash functions for CMS*/
    cal_ipv4_hash(coeff=0x04C11DB7) hash1;
    cal_ipv4_hash(coeff=0x1EDC6F41) hash2;
    cal_ipv4_hash(coeff=0xA833982B) hash3;
    /*Hash function for BitMap*/
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash;
  
    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    table ipv4_host {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            send; drop;
        }

        size = IPV4_HOST_SIZE;
    }

    table ipv4_lpm {
        key     = { hdr.ipv4.dst_addr : lpm; }
        actions = { send; drop; }
        size           = IPV4_LPM_SIZE;
    }

    apply {
        if (hdr.ipv4.isValid()) {
            if (!ipv4_host.apply().hit) {
                ipv4_lpm.apply();
            }
            update_intimeReg.execute(0);
        }

        bit<(MAX_BH_begin)> bm_hash;
        hash_t hash_32_1;
        hash_t hash_32_2;
        hash_t hash_32_3;
        data_t index1;
        data_t index2;
        data_t index3;
        bit<32> value_1;
        bit<32> value_2;
        bit<32> value_3;



        hash1.apply(hdr, hash_32_1);
        hash2.apply(hdr, hash_32_2);
        hash3.apply(hdr, hash_32_3);

      
        bm_hash = (hash.get({
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
                })[MAX_BH:0]);


        index1[MAX_BH:0] = bm_hash;
        index2[MAX_BH:0] = bm_hash;
        index3[MAX_BH:0] = bm_hash;

        index1[UP:MAX_BH_begin] = hash_32_1[6:0];
        index2[UP:MAX_BH_begin] = hash_32_2[6:0];
        index3[UP:MAX_BH_begin] = hash_32_3[6:0];

        if( hash_32_1[MAX_H:MAX_H_min] == 3w0){
        meta.res_1 = update_cms1_0.execute(index1);
        }else if (hash_32_1[MAX_H:MAX_H_min] == 3w1){
        meta.res_1 = update_cms1_1.execute(index1);
        }else if (hash_32_1[MAX_H:MAX_H_min] == 3w2){
        meta.res_1 = update_cms1_2.execute(index1);
        }else if (hash_32_1[MAX_H:MAX_H_min] == 3w3){
        meta.res_1 = update_cms1_3.execute(index1);
        }else if (hash_32_1[MAX_H:MAX_H_min] == 3w4){
        meta.res_1 = update_cms1_4.execute(index1);
        }else if (hash_32_1[MAX_H:MAX_H_min] == 3w5){
        meta.res_1 = update_cms1_5.execute(index1);
        }else if (hash_32_1[MAX_H:MAX_H_min] == 3w6){
        meta.res_1 = update_cms1_6.execute(index1);
        }else if (hash_32_1[MAX_H:MAX_H_min] == 3w7){
        meta.res_1 = update_cms1_7.execute(index1);
        }
    if( hash_32_2[MAX_H:MAX_H_min] == 3w0){
        meta.res_2 = update_cms2_0.execute(index2);
        }else if (hash_32_2[MAX_H:MAX_H_min] == 3w1){
        meta.res_2 = update_cms2_1.execute(index2);
        }else if (hash_32_2[MAX_H:MAX_H_min] == 3w2){
        meta.res_2 = update_cms2_2.execute(index2);
        }else if (hash_32_2[MAX_H:MAX_H_min] == 3w3){
        meta.res_2 = update_cms2_3.execute(index2);
        }else if (hash_32_2[MAX_H:MAX_H_min] == 3w4){
        meta.res_2 = update_cms2_4.execute(index2);
        }else if (hash_32_2[MAX_H:MAX_H_min] == 3w5){
        meta.res_2 = update_cms2_5.execute(index2);
        }else if (hash_32_2[MAX_H:MAX_H_min] == 3w6){
        meta.res_2 = update_cms2_6.execute(index2);
        }else if (hash_32_2[MAX_H:MAX_H_min] == 3w7){
        meta.res_2 = update_cms2_7.execute(index2);
        }
    if( hash_32_3[MAX_H:MAX_H_min] == 3w0){
        meta.res_3 = update_cms3_0.execute(index3);
        }else if (hash_32_3[MAX_H:MAX_H_min] == 3w1){
        meta.res_3 = update_cms3_1.execute(index3);
        }else if (hash_32_3[MAX_H:MAX_H_min] == 3w2){
        meta.res_3 = update_cms3_2.execute(index3);
        }else if (hash_32_3[MAX_H:MAX_H_min] == 3w3){
        meta.res_3 = update_cms3_3.execute(index3);
        }else if (hash_32_3[MAX_H:MAX_H_min] == 3w4){
        meta.res_3 = update_cms3_4.execute(index3);
        }else if (hash_32_3[MAX_H:MAX_H_min] == 3w5){
        meta.res_3 = update_cms3_5.execute(index3);
        }else if (hash_32_3[MAX_H:MAX_H_min] == 3w6){
        meta.res_3 = update_cms3_6.execute(index3);
        }else if (hash_32_3[MAX_H:MAX_H_min] == 3w7){
        meta.res_3 = update_cms3_7.execute(index3);
        }


        value_1 = update_occ1.execute((bit<32>)hash_32_1);
        value_2 = update_occ2.execute((bit<32>)hash_32_2);
        value_3 = update_occ3.execute((bit<32>)hash_32_3);

        bit<32> d12;
        bit<32> d13;
        bit<32> d23;
        /*bit_t dmin;*/
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
        if (meta.count_min == DDoS_threshold + 1 ){
            ig_dprsr_md.digest_type = 1;  
        }

    }
}

/*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Digest<digest_t>() digest; 
    apply {
        if(ig_dprsr_md.digest_type == 1){
            digest.pack({hdr.ipv4.dst_addr});
        }
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

/***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

/***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    Register<data_t, data_t>(1) timeReg;
    RegisterAction<data_t, data_t, data_t>(timeReg)
        update_timeReg = {
            void apply(inout data_t value) {
                value = (bit<32>)eg_prsr_md.global_tstamp;
            }
        };

    apply {
        update_timeReg.execute(0);
    }
}

/*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
    ) pipe;

    Switch(pipe) main;
