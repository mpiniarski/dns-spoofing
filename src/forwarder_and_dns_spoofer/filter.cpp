#include "filter.h"

#include <sstream>
#include <cstring>
#include <libnet.h>
#include <iostream>
#include <linux/if_ether.h>


std::string createFilter(std::string interface_name) {
    std::string myMacAddress = getMacAddress(interface_name);
    std::string myIpAddress = getIpAddress(interface_name);

    std::stringstream str;
    str << "ether dst " << myMacAddress;
    // str << " and dst host " << ip;
    str << " and not dst host " << myIpAddress;
    return str.str();
}

std::string getIpAddress(std::string interface_name) {
    struct ifreq interface_struct;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    /* I want to get an IPv4 IP address */
    interface_struct.ifr_addr.sa_family = AF_INET;
    /* I want IP address attached to "eth0" */
    strncpy(interface_struct.ifr_name, interface_name.c_str(), IFNAMSIZ - 1);
    int ret = ioctl(fd, SIOCGIFADDR, &interface_struct);
    if (ret != 0) {
        std::cerr << "Error occurs when searching for an ip!\n";
    }
    std::string ip = inet_ntoa(((struct sockaddr_in *) &interface_struct.ifr_addr)->sin_addr);
    // TODO inet_ntoa wymaga zaciągnięcia tu całego libnet.h, może jakaś inna funkcja?
    close(fd);
    return ip;
}

std::string getMacAddress(std::string interface_name) {
    std::stringstream mac_address;
    unsigned char mac_array[6];
    struct ifreq interface_struct;          // interface structure -> needed for interface identification
    int fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));        // get socket's descriptor no
    strncpy(interface_struct.ifr_name, interface_name.c_str(), IFNAMSIZ); // read interface name and save it to interface_struct
    if (fd < 0) {
        std::cerr << "Problem in socket creation\n";
    };
    if (ioctl(fd, SIOCGIFFLAGS, &interface_struct) == 0) {
        if (ioctl(fd, SIOCGIFHWADDR, &interface_struct) == 0) {
            memcpy(mac_array, interface_struct.ifr_hwaddr.sa_data, 6);
            for (int i = 0; i < 6; i++) {
                int j = mac_array[i];
                mac_address << std::hex << j;
                if (i != 5) mac_address << ":";
            }
        }
    }
    close(fd);
    return mac_address.str();
}