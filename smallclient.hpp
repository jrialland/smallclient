#ifndef SMALLCLIENT_HPP
#define SMALLCLIENT_HPP
#pragma once

#define SMALLCLIENT_SSL_SUPPORT
#define SMALLCLIENT_SSL_VERIFY 1

// If you want to remove SSl support from the library, define the SMALLCLIENT_NO_SSL_SUPPORT directive
#ifdef SMALLCLIENT_NO_SSL_SUPPORT
#undef SMALLCLIENT_SSL_SUPPORT
#endif

// If you want to remove SSL certificate verification (not recommanded), define the SMALLCLIENT_SSL_NO_VERIFY directive
#ifdef SMALLCLIENT_SSL_NO_VERIFY
#define SMALLCLIENT_SSL_VERIFY 0
#endif

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

// openssl
#ifdef SMALLCLIENT_SSL_SUPPORT
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#include <algorithm>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

#ifndef SMALLCLIENT_READ_BUFFER_SIZE
#define SMALLCLIENT_READ_BUFFER_SIZE 8192
#endif

namespace smallclient
{

    struct URI
    {
        std::string protocol;
        std::string host;
        std::string resource;
        std::string querystring;
        int port;
        URI(const std::string &uri);
        std::string path() const;
        URI &parameter(const std::string &key, const std::string &value);
    };

    std::ostream &operator<<(std::ostream &os, const URI &uri);

    std::string urlencode(const std::string &s);

    std::string urldecode(const std::string &s);

    struct ResponseCallback
    {
        std::function<void(int, const std::string&)> on_start = [](int, const std::string&) {};
        std::function<void(const std::string &, const std::string &)> on_header = [](const std::string &k, const std::string &v) {};
        std::function<void(ssize_t)> on_start_body = [](ssize_t) {};
        std::function<void(const char *, size_t len)> on_data = [](const char *, size_t) {};
        std::function<void()> on_end = []() {};
    };

    void query(const URI &uri, const std::string &method, const std::map<std::string, std::string> &headers, std::istream &data, const ResponseCallback &callback);

    struct Request
    {
    protected:
        Request(const std::string &method, const std::string &uri);

    public:
        std::string method;
        URI uri;
        std::map<std::string, std::string> headers;
        std::istream *data;
        ResponseCallback callback;
        std::string string_data;
        virtual ~Request();
        bool follow_redirects_ = false;
        void execute();
        static Request get(const std::string &uri);
        static Request post(const std::string &uri);
        static Request put(const std::string &uri);
        static Request delete_(const std::string &uri);
        static Request head(const std::string &uri);
        static Request for_method(const std::string &method, const std::string &uri);
        Request &parameter(const std::string &key, const std::string &value);
        Request &header(const std::string &key, const std::string &value);
        Request &body(std::istream &data);
        Request &body(const std::string &s);
        Request &follow_redirects();
    };

};

#endif // SMALLCLIENT_HPP