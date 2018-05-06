#ifndef DNS_SPOOFING_HELPER_H
#define DNS_SPOOFING_HELPER_H

#include <libnet.h>

#include <pcap.h>

#include <arpa/inet.h>
#include <linux/kernel.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <unistd.h>
#include <thread>
#include <chrono>
#include <iostream>
#include <string>
#include <sstream>
#include <csignal>

libnet_t *ln;
char *errbuf;
char* address;
pcap_t *handle;

char *interface_name;
char *deafault_gateway_mac;

struct DNS_HEADER {
    __be16 transId;
    __be16 flags;             // (1) first bit tells if it is request (bit == 0)
    __be16 questNo;           // (2) tells how many requests (almost always 1)
    __be16 other[3];
};

struct QUESTION{
    __be16 qtype;
    __be16 qclass;
};

void stop(int signal) {
    libnet_destroy(ln);
    pcap_close(handle);
    free(errbuf);
    exit(EXIT_SUCCESS);
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
    close(fd);
    return ip;
}

std::string createFilter(char *interface_name, std::string gatewayIp) {
    std::string myMacAddress = getMacAddress(interface_name);
    std::string myIpAddress = getIpAddress(interface_name);

    std::stringstream str;
    str << "ether dst " << myMacAddress;
    // str << " and dst host " << ip;
    str << " and not dst host " << myIpAddress;
    return str.str();
}

void printFromToInfo(ethhdr *eth_hdr) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x -> ",
           eth_hdr->h_source[0], eth_hdr->h_source[1], eth_hdr->h_source[2],
           eth_hdr->h_source[3], eth_hdr->h_source[4], eth_hdr->h_source[5]);
    printf("%02x:%02x:%02x:%02x:%02x:%02x ",
           eth_hdr->h_dest[0], eth_hdr->h_dest[1], eth_hdr->h_dest[2],
           eth_hdr->h_dest[3], eth_hdr->h_dest[4], eth_hdr->h_dest[5]);
    printf("\n");
}

uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

//! \brief
//!     Calculate the UDP checksum (calculated with the whole
//!     packet).
//! \param buff The UDP packet.
//! \param len The UDP packet length.
//! \param src_addr The IP source address (in network format).
//! \param dest_addr The IP destination address (in network format).
//! \return The result of the checksum.
uint16_t udp_checksum(void *buff, size_t len, in_addr_t src_addr, in_addr_t dest_addr) {
    const uint16_t *buf = (uint16_t*) buff;
    uint16_t *ip_src = (uint16_t *) src_addr;
    uint16_t *ip_dst = (uint16_t *) dest_addr;
    uint32_t sum;
    size_t length=len;

    // Calculate the sum
    sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if ( len & 1 )
        // Add the padding if the packet lenght is odd
        sum += *((uint8_t *)buf);

    sum += *(ip_src++);
    sum += *ip_src;

    sum += *(ip_dst++);
    sum += *ip_dst;

    sum += htons(IPPROTO_UDP);
    sum += htons(length);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Return the one's complement of sum
    return ( (uint16_t)(~sum)  );
}



#endif //DNS_SPOOFING_HELPER_H
