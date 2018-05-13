#pragma once

#include <libnet.h>

void arp_spoof(char *interface_name, char *default_gateway_ip);
void libnet_build_arp_spoof(char *default_gateway_ip, libnet_context *ln);

