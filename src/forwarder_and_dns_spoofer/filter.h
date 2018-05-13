#pragma once

#include <string>

std::string createFilter(char *interface_name); // TODO interface_name też jako string?

//TODO sprawdzić, czy przypadkiem do tych funkcji systemowych ioctl się nie odwołujemy w
// wielu miejscach, jak tak to lepiej by to było zrobić raz na początku i przekazywać dalej
std::string getIpAddress(std::string interface_name);

std::string getMacAddress(std::string interface_name);


