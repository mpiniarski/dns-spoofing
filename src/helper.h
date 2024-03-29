#pragma once

#include <memory>
#include <map>

static std::map<std::string, char *> spoofMap;

void stop(int signal);

int readConfigFile();

std::shared_ptr<std::map<std::string, char *>> getSpoofMap();
