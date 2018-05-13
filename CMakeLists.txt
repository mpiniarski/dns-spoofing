cmake_minimum_required(VERSION 3.10)
project(dns_spoofing)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -lnet -pthread -lpcap")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

add_executable(dns_spoofing
        src/dnspoof.cpp
        src/arp_spoofer/arp_spoofer.cpp
        src/arp_spoofer/arp_spoofer.h
        src/forwarder_and_dns_spoofer/forwarder_and_dns_spoofer.cpp
        src/forwarder_and_dns_spoofer/forwarder_and_dns_spoofer.h
        src/forwarder_and_dns_spoofer/filter.cpp
        src/forwarder_and_dns_spoofer/filter.h
        src/forwarder_and_dns_spoofer/forwarder.cpp
        src/forwarder_and_dns_spoofer/forwarder.h
        src/forwarder_and_dns_spoofer/dns_spoofer.cpp
        src/forwarder_and_dns_spoofer/dns_spoofer.h
        src/helper.cpp
        src/helper.h
        )



