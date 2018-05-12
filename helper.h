#ifndef DNS_SPOOFING_HELPER_H
#define DNS_SPOOFING_HELPER_H

#include <libnet.h>
#include <pcap.h>
#include <linux/if_ether.h>

#include <map>


static libnet_t *ln;
static char *errbuf;
static pcap_t *handle;

static char *interface_name;
static char *address;
static char *deafault_gateway_mac;

static std::map<std::string, std::string> spoofMap;

#define DNS_ANSWER_SIZE 16

/*
struct dns_answer {
    dns_answer(uint32_t address) :
            name(htons(0xc00c)),
            type(htons(1)),
            dns_class(htons(1)),
            ttl(htonl(0x2dec)),
            data_length(htons(4)),
            address(htonl(address)) {}

    __be16 name;
    __be16 type;
    __be16 dns_class;
    // __be16 padding
    __be32 ttl;
    __be16 data_length;
    // __be16 padding
    __be32 address;
};
 */

struct dns_answer {
    dns_answer(uint32_t address) :
            name(htons(0xc00c)),
            type(htons(1)),
            dns_class(htons(1)),
            ttl1(htons(0x0)),
            ttl2(htons(0x4e)),
            data_length(htons(4)) {
        //TODO
//        __be32 be_address = htonl(address);
//        char *be_address_p = (char *) (&be_address);
//        address1 = (__be16) (*be_address_p);
//        address2 = (__be16) (*(be_address_p + 2));


        address1 = htons(0xacd9);
        address2 = htons(0x1044);
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

void stop(int signal);
int readConfigFile();
std::string getMacAddress(std::string interface_name);
std::string getIpAddress(std::string interface_name);
std::string createFilter(char *interface_name, std::string gatewayIp);
void printFromToInfo(ethhdr *eth_hdr);

#endif //DNS_SPOOFING_HELPER_H
