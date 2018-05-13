#pragma once

#include <zconf.h>

void forward_frame(const u_char *frame, size_t frame_size, char *interface_name, char *default_gateway_mac);
