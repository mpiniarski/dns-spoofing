#pragma once

#include <linux/types.h>
#include <libnet.h>

#define PROTOCOL_UDP 0x11
#define PORT_DNS 53

bool handle_dns_spoofing(const u_char *frame, char *interface_name);

// TODO może tę i libnet_build_arp_spoof przenieść do jakiegoś wspólnego modułu i mieć moduł rozszerzający libneta?
void libnet_build_dns_spoof(__be32 source_ip,
                            __be32 destination_ip,
                            uint16_t destination_udp_port,
                            uint16_t dns_transaction_id,
                            const u_int8_t *data, u_int32_t datalen,
                            libnet_context *ln);


#define DNS_ANSWER_SIZE 16

struct dns_answer { // TODO jakiś inny sposób na paddingi niż stosowanie tylko __be16?
    dns_answer(uint32_t address) :
            name(htons(0xc00c)),
            type(htons(1)),
            dns_class(htons(1)),
            ttl1(htons(0x0)),
            ttl2(htons(0x4e)),
            data_length(htons(4)) {
        //TODO IMPORTANT zamiast na pałę wpisywać :)
//        __be32 be_address = htonl(address);
//        char *be_address_p = (char *) (&be_address);
//        address1 = (__be16) (*be_address_p);
//        address2 = (__be16) (*(be_address_p + 2));


        address1 = htons(0x96FE);
        address2 = htons(0x1E1E);
    }

    __be16 name;
    __be16 type;
    __be16 dns_class;
    __be16 ttl1;
    __be16 ttl2;
    __be16 data_length;
    __be16 address1;
    __be16 address2;
};

struct DNS_HEADER {
    __be16 transId;
    __be16 flags;             // (1) first bit tells if it is request (bit == 0)
    __be16 questNo;           // (2) tells how many requests (almost always 1)
    __be16 other[3];
};

struct QUESTION {
    __be16 qtype;
    __be16 qclass;
};


