#pragma once

#include <linux/types.h>
#include <libnet.h>
#include <iomanip>


#define PROTOCOL_UDP 0x11
#define PORT_DNS 53

bool handle_dns_spoofing(const u_char *frame, char *interface_name);

void libnet_build_dns_spoof(__be32 source_ip,
                            __be32 destination_ip,
                            uint16_t destination_udp_port,
                            uint16_t dns_transaction_id,
                            const u_int8_t *data, u_int32_t datalen,
                            libnet_context *ln);


#define DNS_ANSWER_SIZE 16

struct dns_answer {
    dns_answer(unsigned char* address) :
        name(htons(0xc00c)),
        type(htons(1)),
        dns_class(htons(1)),
        ttl1(htons(0x0)),
        ttl2(htons(0x4e)),
        data_length(htons(4)) {
            std::stringstream stream, stream2;
            stream << "0x" << std::setfill ('0') << std::setw(sizeof(char)*2) <<
                   std::hex << (int)address[0] << (int)address[1];
            stream2 << "0x" << std::setfill ('0') << std::setw(sizeof(char)*2) <<
               std::hex << (int)address[2] << (int)address[3];

            int number1 = (int)strtol(stream.str().c_str(), nullptr, 0);
            int number2 = (int)strtol(stream2.str().c_str(), nullptr, 0);
            address1 = htons(number1);
            address2 = htons(number2);
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


