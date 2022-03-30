This is a small http client library for C++.

It has the following features:

* Compiles with C++11
* Has support for https, using [OpenSSL](https://www.openssl.org/)
* Allows to simply remove https support at compilation
* Supports [Chuncked transfer encoding](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Transfer-Encoding#chunked)
* Supports automatic following of 301 & 302 redirects 

Compiling
---------

* Example using CMake

```cmake
cmake_minimum_required(VERSION 3.7)
project(myapp)

set(CMAKE_CXX_STANDARD 11) # minimum C++ standard

find_package(OpenSSL REQUIRED)

set(SOURCE_FILES main.cpp libs/smallclient/smallclient.cpp)

add_executable(myapp ${SOURCE_FILES})
target_include_directories(myapp PRIVATE libs/smallclient)
target_link_libraries(myapp OpenSSL::SSL)

# optional compilation settings
target_compile_definitions(myapp
    PUBLIC SMALLCLIENT_READ_BUFFER_SIZE=8192
    PUBLIC SMALLCLIENT_SSL_VERIFY=1
)
```

Compile without Support for SSL
-------------------------------
```cpp
#define SMALLCLIENT_NO_SSL_SUPPORT
#include "smallclient.hpp"

```

Examples
--------

* Simple GET request
--------------------
```cpp
using namespace smallclient;

Request::get("https://example.com/?param=value").execute();
// or
Request::get("https://example.com").parameter("param", "value").execute();

```

* JSON POST

```cpp
    // posted json data
    std::string payload="{'test':'example', 'intvalue':42}";
    std::replace(payload.begin(), payload.end(), '\'', '"');

    // response will be stored here
    std::string result;

    auto request = Request::post("https://example.com/api")
        .header("Content-Type", "application/json")
        .body(payload);

    // fail if response is not ok
    request.callback.on_start = [](int status_code, const std::string& message) {
        if(status_code != 200) {
            throw std::runtime_error(std::to_string(status_code) + " " + message);
        }
    };

    // get json response into result
    request.callback.on_data = [&result](const char*data, int len) {
        result.append(std::string(data, len));
    };

    request.execute();

    std::cout << result << std::endl;
```

* PUT a file

```cpp
    std::ifstream file;
    file.open("myfile.txt", ios_base::in | ios_base::binary);

    URI uri("https://server/dav/folder/myfile.txt");

    ResponseCallback rc;
    rc.on_start = [](int status_code, const std::string& message) {
        std::cout << status_code << " " << message << std::endl;
    };

    query(uri, "PUT", {}, file, callback);

```

* Following redirects

```
    Request::get("https://example.com/?param=value")
         .follow_redirects()
         .execute();
```




