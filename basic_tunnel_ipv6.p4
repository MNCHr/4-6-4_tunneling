/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// const bit<16> TYPE_MYTUNNEL = 0x1212;
// const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header myTunnel_t {
    bit<16> proto_id;
    bit<16> dst_id;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    bit<32>   srcAddr;
    bit<32>   dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> udp_length;
    bit<16> checksum;
}

struct metadata {
    bit<1> Encap;
    bit<1> Decap;
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    myTunnel_t   myTunnel;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    udp_t        udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
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
            0x86dd: parse_ipv6;
            0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            0x0: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x11: parse_udp;
            default: accept;
        } 
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port; //2 
        hdr.ipv4.ttl = 4;
    }
    // action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
    //     standard_metadata.egress_spec = port; //2 
    //     hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; //ethernet addr check 
    //     hdr.ethernet.dstAddr = dstAddr;
    //     hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    // }

    // table ipv4_lpm {
    //     key = {
    //         hdr.ipv4.dstAddr: ternary;
    //     }
    //     actions = {
    //         ipv4_forward;
    //         drop;
    //         NoAction;
    //     }
    //     const entries = {
    //         32w0x0a0a0000 &&& 32w0xffff0000 : ipv4_forward(2); //10.10.0.0/16 lpm
    //         //32w0b00000010000000100000000000000000 &&& 32w0b11111111111111110000000000000000 : ipv4_forward(2);
    //     }

    //     // size = 1024;
    //     default_action = NoAction();
        
    // }
    
    action ipv6_set_a(bit<128> value_ipv6_srcAddr, bit<128> value_ipv6_dstAddr) {
        hdr.ipv6.setValid();
        meta.Encap = 1;
        hdr.ipv6.srcAddr = value_ipv6_srcAddr;
        hdr.ipv6.dstAddr = value_ipv6_dstAddr;
        hdr.ethernet.etherType = 16w0x86dd; //for v6 header
    }

    // table ipv6_set {
    //     key = {
    //         hdr.ipv4.dstAddr : ternary;
    //     }
    //     actions = {
    //         ipv6_set_a;
    //     }
    //     const entries = {
    //         32w0x0a0a0100 &&& 32w0xffffff00 : ipv6_set_a(128w0x22222222222222220000000000000003, 128w0x22222222222222220000000000000004); //2222:2222:2222:2222::4
    //         32w0x0a0a6400 &&& 32w0xffffff00 : ipv6_set_a(128w0x22222222222222220000000000000004, 128w0x22222222222222220000000000000003); //2222:2222:2222:2222::3
    //     }
    // }

    table ipv6_set_key_udp {
        key = {
            hdr.udp.dstPort : ternary;
        }
        actions = {
            ipv6_set_a;
        }
        const entries = {
            16w0x2ee0 &&& 16w0xffff : ipv6_set_a(128w0x22222222222222220000000000000003, 128w0x22222222222222220000000000000004); //2222:2222:2222:2222::4, client->server
            16w0x2715 &&& 16w0xffff : ipv6_set_a(128w0x22222222222222220000000000000004, 128w0x22222222222222220000000000000003); //2222:2222:2222:2222::3, server->client
        }
    }

    action ipv6_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port; //=1
        hdr.ipv6.hopLimit = 6;
    }

    table ipv6_lpm {
        key = {
            hdr.udp.dstPort : exact;
            hdr.ipv6.dstAddr : ternary; //64
        }
        actions = {
            ipv6_forward;
            drop;
            NoAction;
        }
        // size = 1024;
        default_action = drop();
        const entries = {
            (16w0x2ee0, 128w0x22222222222222220000000000000000 &&& 128w0xFFFFFFFFFFFFFFFF0000000000000000) : ipv6_forward(1) ;            
            (16w0x2715, 128w0x22222222222222220000000000000000 &&& 128w0xFFFFFFFFFFFFFFFF0000000000000000) : ipv6_forward(2) ;
        }
        //drop();   
    }
    
    action ipv6_decap_a() {
        hdr.ipv6.setInvalid();
        meta.Decap = 1;
        hdr.ethernet.etherType = 16w0x800;
    }
    
    table ipv6_decap {
        key = {

        }
        actions = {
            ipv6_decap_a;
        }
        default_action = ipv6_decap_a;
    }

    action udp_forward(egressSpec_t port, bit<48> srceth_value, bit<48> dsteth_value, 
                                          bit<32> srcip_value, bit<32> dstip_value) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = srceth_value;
        hdr.ethernet.dstAddr = dsteth_value;
        hdr.ipv4.srcAddr = srcip_value;
        hdr.ipv4.dstAddr = dstip_value;
        //hdr.ethernet.srcAddr = srcMAC_value;
        //hdr.udp.checksum = 17;
    }

    table udp_exact {
        key = {
            hdr.udp.dstPort : exact;
        }
        actions = {
            drop;
            NoAction;
            udp_forward;
        }
        default_action = drop();
        const entries = {
            16w0x2ee0 : udp_forward(1, 48w0xfa163e0f19e4, 48w0xfa16e337f065, 32w0x0a0a6405, 32w0x0a0a010c); //client -> server, dstport 12000  32w0x0a0a6405
            16w0x2715 : udp_forward(2, 48w0xfa163e2101ab, 48w0xfa163e8d4f06, 32w0x0a0a010c, 32w0x0a0a6405); //server -> client, dstport 10005   48w0xfa163e6e3b72
        }
    }
    
    apply {
        if (!hdr.ipv6.isValid() && hdr.udp.isValid()) { //encap
            ipv6_set_key_udp.apply(); //v6 src, dst addr, ethertype header value setting
            ipv6_lpm.apply();            
        }
        else if (hdr.ipv6.isValid() && hdr.udp.isValid()) { //decap
            ipv6_decap.apply();
            udp_exact.apply();
        }
    }


//////////////////////////////////////////////////////////////////
        // if (hdr.ipv4.isValid() && !hdr.ipv6.isValid()) { //encap
        //     hdr.ethernet.etherType = 16w0x86dd;
        //     hdr.ipv6.setValid();
        //     ipv6_set.apply();
        //     ipv6_lpm.apply();
        // }
        
        // else if(hdr.ipv6.isValid()) { //decap
        //     hdr.ipv6.setInvalid();
        //     hdr.ethernet.etherType = 16w0x800;
        //     ipv4_lpm.apply();
        //}
    //}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ipv4);      
        packet.emit(hdr.udp);  
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
