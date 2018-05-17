#include "forwarder.h"
#include "../helper.h"

#include <linux/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <cstring>
#include <stropts.h>
#include <bits/ioctls.h>
#include <linux/if_packet.h>
#include <libnet.h>

void forward_frame(const u_char *frame, size_t frame_size, char *interface_name, char *default_gateway_mac) {
    int sfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    // Get interface name
    struct ifreq interface_struct;          // interface structure -> needed for interface identification
    strncpy(interface_struct.ifr_name, interface_name, IFNAMSIZ);
    ioctl(sfd_send, SIOCGIFINDEX, &interface_struct);

    // Init send address
    struct sockaddr_ll sall_send;
    memset(&sall_send, 0, sizeof(struct sockaddr_ll));
    sall_send.sll_family = AF_PACKET;
    sall_send.sll_protocol = htons(ETH_P_ALL);
    sall_send.sll_ifindex = interface_struct.ifr_ifindex;
    sall_send.sll_hatype = ARPHRD_ETHER;
    sall_send.sll_pkttype = PACKET_OUTGOING;
    sall_send.sll_halen = ETH_ALEN;
    struct ethhdr *eth_hdr = (struct ethhdr *) frame;


    sscanf(default_gateway_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &sall_send.sll_addr[0], &sall_send.sll_addr[1], &sall_send.sll_addr[2],
           &sall_send.sll_addr[3], &sall_send.sll_addr[4], &sall_send.sll_addr[5]);
    memcpy(eth_hdr->h_dest, &sall_send.sll_addr, ETH_ALEN);
    // Change source address to this computer MAC
    ioctl(sfd_send, SIOCGIFHWADDR, &interface_struct);
    memcpy(eth_hdr->h_source, &interface_struct.ifr_hwaddr.sa_data, ETH_ALEN);
    // SEND FRAME
    // Change destination address to default gateway MAC
    if (sendto(sfd_send, frame, (int) (frame_size), 0, (struct sockaddr *) &sall_send, sizeof(struct sockaddr_ll)) < 0) {
        printf("Error while sending: %s\n", strerror(errno));
    }
    close(sfd_send);
}