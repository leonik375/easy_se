cmake_minimum_required(VERSION 3.22)
# Authoritative version lives in git tags; this is the baseline for
# untagged source checkouts (overridden by CI when building from a tag).
project(easy_se VERSION 0.1.0 LANGUAGES CXX)

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

# ---- Linux CLI (also the easy_se_cli daemon used by the systemd unit) ----
if(NOT CMAKE_CROSSCOMPILING AND NOT ANDROID)
    find_package(Threads REQUIRED)
    add_executable(easy_se_cli easy_se_cli.cpp)
    target_link_libraries(easy_se_cli PRIVATE easy_se Threads::Threads)
    target_include_directories(easy_se_cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

    # Fully-static binary (CI builds this on Alpine/musl for the
    # distro-agnostic tarball).  Enabled by -DEASY_SE_STATIC_CLI=ON.
    option(EASY_SE_STATIC_CLI "Link easy_se_cli statically" OFF)
    if(EASY_SE_STATIC_CLI)
        target_link_options(easy_se_cli PRIVATE -static)
    endif()

    include(GNUInstallDirs)
    install(TARGETS easy_se_cli RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()
