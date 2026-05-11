cmake_minimum_required(VERSION 3.22)
project(easy_se CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- source files ----
add_library(easy_se STATIC
    src/pack.cpp
    src/tunnel.cpp
    src/proxy.cpp
    src/tcp_conn.cpp
    src/easy_se.cpp
)

target_include_directories(easy_se PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(easy_se PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# ---- OpenSSL (prebuilt static libs supplied by build-android-deps.sh) ----
if(DEFINED SE_PREBUILT_DIR)
    target_include_directories(easy_se PRIVATE ${SE_PREBUILT_DIR}/include)
    target_link_libraries(easy_se PRIVATE
        ${SE_PREBUILT_DIR}/lib/libssl.a
        ${SE_PREBUILT_DIR}/lib/libcrypto.a
    )
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(easy_se PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

# ---- Android logging ----
if(ANDROID)
    target_link_libraries(easy_se PRIVATE log)
endif()

# ---- Linux CLI test (only when building natively, not cross-compiling) ----
if(NOT CMAKE_CROSSCOMPILING AND NOT ANDROID)
    find_package(Threads REQUIRED)
    add_executable(easy_se_cli easy_se_cli.cpp)
    target_link_libraries(easy_se_cli PRIVATE easy_se Threads::Threads)
    target_include_directories(easy_se_cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
endif()
