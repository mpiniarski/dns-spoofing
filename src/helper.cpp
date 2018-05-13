#include <arpa/inet.h>
#include <linux/kernel.h>
#include <sys/ioctl.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>

#include "helper.h"

void stop(int signal) {
    exit(EXIT_SUCCESS);
}

std::shared_ptr<std::map<std::string, std::string>> getSpoofMap() {
    return std::make_shared<std::map<std::string, std::string>>(spoofMap);
}

std::string getDomain(std::string site) {
    std::istringstream iss(site);
    std::vector<std::string> tokens;
    std::string token;
    while (std::getline(iss, token, '.')) {
        if (!token.empty())
            tokens.push_back(token);
    }
    if (tokens.size() >= 2) {
        std::stringstream str;
        str << tokens.at(tokens.size() - 2);
        return str.str();
    }
    return "";
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
            if (std::getline(is_line, addressTo)) {
                std::string addressFromDomain = getDomain(addressFrom);
                spoofMap[addressFromDomain] = addressTo;
            }
        }
    }
    file.close();
    return 0;
}


