cmake_minimum_required(VERSION 3.10)
project(dns_spoofing)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -Wall -lnet -pthread -lpcap")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin")

add_executable(dns_spoofing dnspoof.cpp helper.h)



