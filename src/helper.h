#pragma once

#include <libnet.h>
#include <pcap.h>
#include <linux/if_ether.h>

#include <map>

static std::map<std::string, std::string> spoofMap;

void stop(int signal);
int readConfigFile();
void printFromToInfo(ethhdr *eth_hdr);
