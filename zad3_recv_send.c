/*
 * Copyright (C) 2018 Michal Kalewski <mkalewski at cs.put.poznan.pl>
 *
 * Compilation:  gcc -Wall ./zad3_recv_send.c -o ./zad3
 * Usage:        ./ethrecv INTERFACE MAC
 * Test:        ./ethrecv lo 00:00:00:00:00:00
 * NOTE:         This program requires root privileges.
 *
 * Bug reports:  https://gitlab.cs.put.poznan.pl/mkalewski/ps-2018/issues
 *
 */

#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>

#define ETH_P_CUSTOM 0x8888

int main(int argc, char** argv) {
  int sfd;                  // descriptor no
  char* frame;              // pointer to received frame
  char* fdata;              // pointer to data in received frame
  struct ethhdr* fhead;     // structure for received frame's header
  struct ifreq ifr;         // structure interface
  struct sockaddr_ll sall;  // structure for socket

  sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_CUSTOM));  // read descriptor
  strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);                // read interface name from argv[1]
  ioctl(sfd, SIOCGIFINDEX, &ifr);                          // get interface index
  memset(&sall, 0, sizeof(struct sockaddr_ll));            // fill sall structure with zeros
  // FILL sall structure with info:
  sall.sll_family = AF_PACKET;                            // Always AF_PACKET
  sall.sll_protocol = htons(ETH_P_CUSTOM);                // Physical-layer protocol
  sall.sll_ifindex = ifr.ifr_ifindex;                     // Interface number
  sall.sll_hatype = ARPHRD_ETHER;
  sall.sll_pkttype = PACKET_HOST;
  sall.sll_halen = ETH_ALEN;                              // MAC address size
  // bind sfd descriptor with sall structure:
  bind(sfd, (struct sockaddr*) &sall, sizeof(struct sockaddr_ll));

  // SENDING
  int sfd_send, ifindex;                           // descriptor no (to send to)
  struct sockaddr_ll sall_send;                    // structure to send

  sfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_CUSTOM));
  strncpy(ifr.ifr_name, argv[1], IFNAMSIZ);
  ioctl(sfd_send, SIOCGIFINDEX, &ifr);
  ifindex = ifr.ifr_ifindex;
  ioctl(sfd_send, SIOCGIFHWADDR, &ifr);
  memset(&sall_send, 0, sizeof(struct sockaddr_ll));
  sall_send.sll_family = AF_PACKET;
  sall_send.sll_protocol = htons(ETH_P_CUSTOM);
  sall_send.sll_ifindex = ifindex;
  sall_send.sll_hatype = ARPHRD_ETHER;
  sall_send.sll_pkttype = PACKET_OUTGOING;
  sall_send.sll_halen = ETH_ALEN;
  // read receiver's MAC address and save it to sall_send
  sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &sall_send.sll_addr[0], &sall_send.sll_addr[1], &sall_send.sll_addr[2],
         &sall_send.sll_addr[3], &sall_send.sll_addr[4], &sall_send.sll_addr[5]);

  int counter = 1;
  while(1) {
    frame = malloc(ETH_FRAME_LEN);      // alloc memory for frame
    memset(frame, 0, ETH_FRAME_LEN);    // fill frame with zeros
    fhead = (struct ethhdr*) frame;     // cast frame to header
    fdata = frame + ETH_HLEN;           // fdata points to data in frame

    // -------RECEIVE FRAME----------
    printf("------------------------------------\n");
    printf("RECEIVING:\n");

    struct sockaddr_ll sall_recv;
    memset(&sall_recv, 0, sizeof(struct sockaddr_ll));

    socklen_t sl = sizeof(struct sockaddr_ll);
    ssize_t len;
    len = recvfrom(sfd, frame, ETH_FRAME_LEN, 0, (struct sockaddr*) &sall_recv, &sl);

    // print received data
    printf("[%dB] %02x:%02x:%02x:%02x:%02x:%02x -> ", (int)len,
           fhead->h_source[0], fhead->h_source[1], fhead->h_source[2],
           fhead->h_source[3], fhead->h_source[4], fhead->h_source[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x | ",
           fhead->h_dest[0], fhead->h_dest[1], fhead->h_dest[2],
           fhead->h_dest[3], fhead->h_dest[4], fhead->h_dest[5]);
    printf(" PacketType:%d, EtherType:%d\n", sall_recv.sll_pkttype, sall_recv.sll_protocol);
    printf("%s\n", fdata);

    // ------SEND FRAME------------
    printf("SENDING: %d\n", counter);

    sfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_CUSTOM));
    memcpy(fhead->h_dest, &sall_send.sll_addr, ETH_ALEN);
    memcpy(fhead->h_source, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    fhead->h_proto = htons(ETH_P_CUSTOM);

    if (sendto(sfd_send, frame, (int)len, 0,(struct sockaddr*) &sall_send, sizeof(struct sockaddr_ll)) < 0) {
      printf("SENDTO FAILED!!!!!!!!!!!: %s\n", strerror(errno));
  } else printf("Message sent!\n");
    close(sfd_send);

    free(frame);
    printf("------------------------------------\n\n");
    counter++;
  }
  close(sfd);
  return EXIT_SUCCESS;
}
