#include <arpa/inet.h>
#include <linux/kernel.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>

#include "helper.h"

void stop(int signal) {
    exit(EXIT_SUCCESS);
}

int readConfigFile() {
    std::fstream file;
    file.open("config.cfg");
    if (!file.good())
        file.open("../config.cfg");     // if exec in under bin path
    if (!file.good()) {
        std::cerr << "Input file is incorrect!\n";
        return -1;
    }
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream is_line(line);
        std::string addressFrom;
        if (line.substr(0, 1) == "#") continue;
        if (std::getline(is_line, addressFrom, '=')) {
            std::string addressTo;
            if (std::getline(is_line, addressTo))
                spoofMap[addressFrom] = addressTo;
        }
    }
    file.close();
    return 0;
}


void printFromToInfo(ethhdr *eth_hdr) { // TODO czy to porzebne?
    printf("%02x:%02x:%02x:%02x:%02x:%02x -> ",
           eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2],
           eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x ",
           eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2],
           eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
    printf("\n");
}


