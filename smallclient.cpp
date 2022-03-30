#include "smallclient.hpp"

namespace smallclient
{
    static inline void throw_for_errno(const std::string &message)
    {
        throw std::runtime_error(std::string(message) + " (errno " + std::to_string(errno) + ")" + strerror(errno));
    }

    static inline std::vector<std::string> split(const std::string &s, char delim)
    {
        std::vector<std::string> elems;
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, delim))
        {
            elems.push_back(item);
        }
        return elems;
    }

    // trim from start (in place)
    static inline void ltrim(std::string &s)
    {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch)
                                        { return !std::isspace(ch); }));
    }

    // trim from end (in place)
    static inline void rtrim(std::string &s)
    {
        s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch)
                             { return !std::isspace(ch); })
                    .base(),
                s.end());
    }

    // trim from both ends (in place)
    static inline void trim(std::string &s)
    {
        ltrim(s);
        rtrim(s);
    }

    static inline std::function<bool(std::string &, const std::string &)> make_getline(std::function<ssize_t(void *, size_t)> read_fn)
    {
        return [read_fn](std::string &s, const std::string &delim)
        {
            s.clear();
            char c;
            int pos = 0;
            int len = 0;
            while (read_fn(&c, sizeof(char)) > 0)
            {
                len += 1;
                if (len >= SMALLCLIENT_READ_BUFFER_SIZE)
                {
                    throw std::runtime_error("Buffer overflow (SMALLCLIENT_READ_BUFFER_SIZE exceeded)");
                }
                s += c;
                if (c == delim[pos])
                {
                    pos += 1;
                    if (pos == delim.size())
                    {
                        s = s.substr(0, s.size() - delim.size());
                        return true;
                    }
                }
                else
                {
                    pos = 0;
                }
            }
            return false;
        };
    }

    struct Out
    {
        std::function<ssize_t(const char *buf, size_t len)> write;

        ssize_t writestr(const std::string &s)
        {
            return write(s.c_str(), s.length());
        }
    };

    struct In
    {
        std::function<void(std::string &dest, const std::string &sep)> getline;
        std::function<ssize_t(void *, size_t)> read;
        std::function<void(void)> close;
    };

    URI::URI(const std::string &uri)
    {
        std::string myuri(uri);
        int pos = myuri.find("://");
        if (pos == std::string::npos)
        {
            throw std::runtime_error("Invalid URI (no ://)");
        }
        else
        {
            protocol = uri.substr(0, pos);
            if (protocol == "http")
            {
                port = 80;
            }
            else if (protocol == "https")
            {
                port = 443;
            }
            else
            {
                throw std::runtime_error("Invalid URI (protocol)");
            }
            myuri = myuri.substr(pos + 3);
        }
        pos = myuri.find("/");
        if (pos == std::string::npos)
        {
            pos = myuri.size();
        }
        std::string hostPort = myuri.substr(0, pos);
        if (hostPort.find(":") != std::string::npos)
        {
            std::vector<std::string> hostPortSplit = split(hostPort, ':');
            host = hostPortSplit[0];
            port = atoi(hostPortSplit[1].c_str());
        }
        else
        {
            host = hostPort;
        }
        resource = myuri.substr(pos);
        pos = resource.find("?");
        if (pos != std::string::npos)
        {
            querystring = resource.substr(pos + 1);
            resource = resource.substr(0, pos);
        }
        if (resource.empty())
        {
            resource = "/";
        }
    }

    std::string URI::path() const
    {
        std::string path(resource);
        if (querystring.size())
        {
            path += "?" + querystring;
        }
        return path;
    }

    std::ostream &operator<<(std::ostream &os, const URI &uri)
    {
        std::string portspec;
        if ((uri.protocol == "http" && uri.port != 80) || (uri.protocol == "https" && uri.port != 443))
        {
            portspec = ":" + std::to_string(uri.port);
        }
        os << uri.protocol << "://" << uri.host << portspec << uri.path();
        return os;
    }

    URI &URI::parameter(const std::string &key, const std::string &value)
    {
        if (querystring.empty())
        {
            querystring = key + "=" + urlencode(value);
        }
        else
        {
            querystring += "&" + key + "=" + urlencode(value);
        }
    }

    static inline std::tuple<In, Out, void *> connect(const URI &uri)
    {
        struct addrinfo hints, *result, *rp;
        memset(&hints, 0, sizeof(addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        int getaddrinfo_result =
            getaddrinfo(uri.host.c_str(), std::to_string(uri.port).c_str(), &hints, &result);

        if (getaddrinfo_result != 0)
        {
            throw_for_errno("getaddrinfo");
        }

        int fd = -1;

        for (rp = result; rp != NULL; rp = rp->ai_next)
        {
            fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == -1)
            {
                continue;
            }
            int connect_result = connect(fd, rp->ai_addr, rp->ai_addrlen);
            if (connect_result == -1)
            {
                close(fd);
                fd = -1;
                continue;
            }
            break;
        }

        freeaddrinfo(result);

        if (fd == -1)
        {
            throw_for_errno("connect");
        }

        bool is_ssl = uri.protocol.compare("https") == 0;

        if (is_ssl)
        {
#ifdef SMALLCLIENT_SSL_SUPPORT

            SSL_library_init();

            const SSL_METHOD *sslmethod = TLS_client_method();
            SSL_CTX *ctx = SSL_CTX_new(sslmethod);
            if (ctx == nullptr)
            {
                throw std::runtime_error("SSL_CTX_new failed");
            }

            SSL *ssl = SSL_new(ctx);
            if (ssl == nullptr)
            {
                throw std::runtime_error("SSL_new failed");
            }

            SSL_set_fd(ssl, fd);

            int ssl_connect_result = SSL_connect(ssl);
            if (ssl_connect_result != 1)
            {
                throw std::runtime_error("SSL_connect failed");
            }

            std::function<ssize_t(void *, size_t)> read_fn = [ssl](void *buf, size_t len)
            {
                return SSL_read(ssl, buf, len);
            };

            return std::make_tuple(
                In{
                    .getline = make_getline(read_fn),
                    .read = read_fn,
                    .close = [fd]()
                    {
                        close(fd);
                    }},
                Out{.write = [ssl](const char *s, size_t len)
                    {
                        return SSL_write(ssl, s, len);
                    }},
                ssl);

#else
            close(fd);
            throw std::runtime_error("SSL not supported");
#endif
        }
        else
        {
            std::function<ssize_t(void *, size_t)> read_fn = [fd](void *buf, size_t len)
            {
                return read(fd, buf, len);
            };

            return std::make_tuple(
                In{
                    .getline = make_getline(read_fn),
                    .read = read_fn,
                    .close = [fd]()
                    { close(fd); },
                },
                Out{
                    .write = [fd](const char *buf, size_t len)
                    {
                        return write(fd, buf, len);
                    }},
                nullptr);
        }
    }

    static void query(const URI &uri, const std::string &method, const std::map<std::string, std::string> &headers, std::istream &data, const ResponseCallback &callback)
    {
        char buffer[SMALLCLIENT_READ_BUFFER_SIZE];
        auto t = connect(uri);
        auto input = std::get<0>(t);
        auto output = std::get<1>(t);
        auto ssl = std::get<2>(t);

#ifdef SMALLCLIENT_SSL_SUPPORT
        if (ssl != nullptr && SMALLCLIENT_SSL_VERIFY)
        {
            int err = SSL_get_verify_result(static_cast<SSL *>(ssl));
            if (err != X509_V_OK)
            {

#define SSL_VERIFY_ERROR_CODE(code)                                                                            \
    case code:                                                                                                 \
        throw std::runtime_error("SSL_get_verify_result failed (" + std::to_string(code) + " " + #code + ")"); \
        break;

                switch (err)
                {
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNABLE_TO_GET_CRL)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CERT_SIGNATURE_FAILURE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CRL_SIGNATURE_FAILURE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CERT_NOT_YET_VALID)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CERT_HAS_EXPIRED)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CRL_NOT_YET_VALID)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CRL_HAS_EXPIRED)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_OUT_OF_MEM)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CERT_CHAIN_TOO_LONG)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CERT_REVOKED)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_INVALID_CA)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_PATH_LENGTH_EXCEEDED)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_INVALID_PURPOSE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CERT_UNTRUSTED)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CERT_REJECTED)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_SUBJECT_ISSUER_MISMATCH)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_AKID_SKID_MISMATCH)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_KEYUSAGE_NO_CERTSIGN)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_KEYUSAGE_NO_CRL_SIGN)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_INVALID_NON_CA)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_INVALID_EXTENSION)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_INVALID_POLICY_EXTENSION)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_NO_EXPLICIT_POLICY)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_DIFFERENT_CRL_SCOPE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNNESTED_RESOURCE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_PERMITTED_VIOLATION)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_EXCLUDED_VIOLATION)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_SUBTREE_MINMAX)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_UNSUPPORTED_NAME_SYNTAX)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_CRL_PATH_VALIDATION_ERROR)
                    SSL_VERIFY_ERROR_CODE(X509_V_ERR_APPLICATION_VERIFICATION)
                default:
                    throw std::runtime_error("SSL_get_verify_result failed (code=" + std::to_string(err) + ")");
                    break;
                }

#undef SSL_VERIFY_ERROR_CODE
            }
        }
#endif

        output.writestr(method);
        output.writestr(" ");
        output.writestr(uri.path());
        output.writestr(" HTTP/1.1\r\n");
        output.writestr("Host: " + uri.host + "\r\n");
        for (auto &entry : headers)
        {
            output.writestr(entry.first + ": " + entry.second + "\r\n");
        }
        output.writestr("\r\n"); // end of request headers

        while (data.good())
        {
            data.read(buffer, sizeof(buffer));
            output.write(buffer, data.gcount());
        }

        std::string line;
        input.getline(line, "\r\n");
        auto parts = split(line, ' ');
        if (parts[0].rfind("HTTP/", 0) == 0 && parts.size() >= 3 && parts[0].length() > 0)
        {
            int status_code = std::atoi(parts[1].c_str());
            callback.on_start(status_code, parts[2]);
        }
        else
        {
            throw std::runtime_error("Unexpected status line: " + line);
        }

        bool is_chunked = false;
        bool done = false;
        ssize_t contentLength = -1;

        // read first header line
        input.getline(line, "\r\n");

        while (!line.empty())
        {
            // parse header line
            std::string key = line.substr(0, line.find(':'));
            trim(key);
            std::string value = line.substr(line.find(':') + 1);
            trim(value);

            if (key == "Transfer-Encoding" && value == "chunked")
            {
                is_chunked = true;
            }
            else if (key == "Content-Length")
            {
                contentLength = std::stoi(value);
            }

            callback.on_header(key, value);

            // read next line
            input.getline(line, "\r\n");
        }

        callback.on_start_body(is_chunked ? -1 : contentLength);

        if (is_chunked)
        {
            while (!done)
            {
                std::string chunk_size_str;
                input.getline(chunk_size_str, "\r\n");
                size_t chunk_size = 0;
                if (!chunk_size_str.empty())
                {
                    chunk_size = std::stoi(chunk_size_str, 0, 16);
                }
                if (chunk_size == 0)
                {
                    done = true;
                    break;
                }
                else
                {
                    while (chunk_size > 0)
                    {
                        ssize_t requested_read = std::min(chunk_size, (size_t)SMALLCLIENT_READ_BUFFER_SIZE);
                        int actual_read = input.read(buffer, requested_read);
                        callback.on_data(buffer, actual_read);
                        chunk_size -= actual_read;
                    }
                    input.getline(line, "\r\n"); // consume the trailing \r\n
                }
            }
        }
        else
        {
            while (!done)
            {
                auto len = input.read(buffer, sizeof(buffer));
                if (len == -1)
                {
                    throw_for_errno("read");
                }
                else if (len == 0)
                {
                    done = true;
                }
                else
                {
                    callback.on_data(buffer, len);
                }
            }
        }

        input.close();
        callback.on_end();
    }

    Request::Request(const std::string &method_, const std::string &uri_) : method(method), uri(uri), headers(), data(nullptr)
    {
    }

    Request Request::for_method(const std::string &method_, const std::string &uri)
    {
        return Request(method_, uri);
    }

    Request Request::get(const std::string &uri)
    {
        return for_method("GET", uri);
    }
    Request Request::post(const std::string &uri)
    {
        return for_method("POST", uri);
    }

    Request Request::put(const std::string &uri)
    {
        return for_method("PUT", uri);
    }

    Request Request::delete_(const std::string &uri)
    {
        return for_method("DELETE", uri);
    }

    Request Request::head(const std::string &uri)
    {
        return for_method("HEAD", uri);
    }

    void Request::execute()
    {
        if (data != nullptr)
        {
            query(uri, method, headers, *data, callback);
        }
        else
        {
            if (!string_data.empty())
            {
                headers["Content-Length"] = std::to_string(string_data.size());
            }
            std::istringstream in(string_data);
            query(uri, method, headers, in, callback);
        }
    }

    Request &Request::parameter(const std::string &key, const std::string &value)
    {
        if (method == "POST")
        {
            headers["Content-Type"] = "application/x-www-form-urlencoded";
            if (string_data.empty())
            {
                string_data = key + "=" + urlencode(value);
            }
            else
            {
                string_data += "&" + key + "=" + urlencode(value);
            }
        }
        else
        {
            uri.parameter(key, value);
        }
        return *this;
    }

    Request &Request::header(const std::string &key, const std::string &value)
    {
        headers[key] = value;
        return *this;
    }

    Request &Request::body(std::istream &data)
    {
        this->data = &data;
        return *this;
    }

    Request &Request::body(const std::string &s)
    {
        string_data = s;
        return *this;
    }

    struct RedirectCallback : public ResponseCallback
    {

        Request *request;
        ResponseCallback &original_callback;
        bool redirect;
        int redirect_count = 0;
        std::string location;
        ResponseCallback wrapped;

        RedirectCallback(Request *request_, ResponseCallback &original_callback_) : request(request_),
                                                                                    original_callback(original_callback_),
                                                                                    redirect(false), location()
        {
            on_start = [this](int status_, const std::string &message)
            {
                if (status_ == 301 || status_ == 302)
                {
                    redirect = true;
                }
                else
                {
                    original_callback.on_start(status_, message);
                }
            };

            on_header = [this](const std::string &key, const std::string &value)
            {
                if (key == "Location")
                {
                    location = value;
                }
                if (!redirect)
                {
                    original_callback.on_header(key, value);
                }
            };

            on_start_body = [this](ssize_t content_length)
            {
                if (!redirect)
                {
                    original_callback.on_start_body(content_length);
                }
            };

            on_data = [this](const char *data, size_t len)
            {
                if (!redirect)
                {
                    original_callback.on_data(data, len);
                }
            };

            on_end = [this]()
            {
                if (redirect)
                {
                    if (location.empty())
                    {
                        throw std::runtime_error("Redirection without Location header");
                    }

                    redirect_count += 1;
                    if (redirect_count > 10)
                    {
                        throw std::runtime_error("Too many redirects");
                    }

                    request->uri = URI(location);
                    redirect = false;
                    location = "";
                    request->execute();
                }
                else
                {
                    original_callback.on_end();
                }
            };
        }
    };

    Request &Request::follow_redirects()
    {
        if (!follow_redirects_)
        {
            follow_redirects_ = true;
            callback = RedirectCallback(this, callback);
        }
        return *this;
    }

    std::string urlencode(std::string &s)
    {
        std::string new_str = "";
        char c;
        int ic;
        const char *chars = s.c_str();
        char bufHex[10];
        int len = strlen(chars);

        for (int i = 0; i < len; i++)
        {
            c = chars[i];
            ic = c;
            // uncomment this if you want to encode spaces with +
            /*if (c==' ') new_str += '+';
            else */
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
                new_str += c;
            else
            {
                sprintf(bufHex, "%X", c);
                if (ic < 16)
                    new_str += "%0";
                else
                    new_str += "%";
                new_str += bufHex;
            }
        }
        return new_str;
    }

    std::string urldecode(const std::string &s)
    {
        std::string ret;
        char ch;
        int i, ii, len = s.length();

        for (i = 0; i < len; i++)
        {
            if (s[i] != '%')
            {
                if (s[i] == '+')
                    ret += ' ';
                else
                    ret += s[i];
            }
            else
            {
                sscanf(s.substr(i + 1, 2).c_str(), "%x", &ii);
                ch = static_cast<char>(ii);
                ret += ch;
                i = i + 2;
            }
        }
        return ret;
    }

}
