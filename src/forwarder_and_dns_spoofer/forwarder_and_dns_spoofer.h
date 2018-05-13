#pragma once

#include <string>
#include <linux/types.h>
#include <libnet.h>


void forward_and_dns_spoof(char *interface_name, char *default_gateway_mac);

void trap(u_char *user, const struct pcap_pkthdr *h, const u_char *frame);

