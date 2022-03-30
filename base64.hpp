#ifndef BASE64_HPP
#define BASE64_HPP
#pragma once

#include <string>
#include <functional>

namespace base64
{

    std::string encode(const unsigned char *data, size_t input_length);

    void decode(std::string &encoded_string, std::function<void(const unsigned char *, size_t)> callback);
}

#endif // BASE64_HPP