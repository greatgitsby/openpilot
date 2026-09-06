#pragma once
#include <cstdint>
#include <string>
#include <vector>
void saveCapture(const std::string &path, int width, int height, const std::vector<uint8_t> &bottom_up_rgba);
