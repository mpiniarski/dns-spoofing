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

struct DNS_HEADER {
    __be16 transId;
    __be16 flags;             // (1) first bit tells if it is request (bit == 0)
    __be16 questNo;           // (2) tells how many requests (almost always 1)
    __be16 other[3];
};

struct QUESTION{
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
