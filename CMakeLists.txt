cmake_minimum_required(VERSION 3.20)
project(TimestampNetwork)

set(CMAKE_CXX_STANDARD 17)

# Mac homebrew dependencies
if(APPLE)
    # Tell CMake exactly where Homebrew lives on M-series Macs
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")
    include_directories(/opt/homebrew/include)
endif()

find_package(OpenSSL REQUIRED)

# Force CMake to find the exact libsodium library file
find_library(SODIUM_LIB NAMES sodium PATHS /opt/homebrew/lib /usr/local/lib REQUIRED)

include_directories(include)
include_directories(lib)
include_directories(${OPENSSL_INCLUDE_DIR})

# Rust library setup
if(APPLE)
    set(LIB_EXT "dylib")
else()
    set(LIB_EXT "so")
endif()

set(FROST_RUST_LIB ${CMAKE_SOURCE_DIR}/lib/frostdemo/target/release)

# Define the executables
add_executable(crypto_demo
    src/AlgorithmPlayground.cpp
    src/node.cpp
    src/coordinator.cpp
)

add_executable(node_app
    src/server_main.cpp
    src/node.cpp
    src/coordinator.cpp
)

# Link libraries
set(COMMON_LIBS
    ${FROST_RUST_LIB}/libfrostdemo.${LIB_EXT}
    ${OPENSSL_LIBRARIES}
    ${SODIUM_LIB}
    dl
    pthread
)

target_link_libraries(crypto_demo ${COMMON_LIBS})
target_link_libraries(node_app ${COMMON_LIBS})

# RPATH (Runtime Search Paths)
if(APPLE)
    set_target_properties(crypto_demo node_app PROPERTIES 
        INSTALL_RPATH "@loader_path/../lib/frostdemo/target/release"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
else()
    set_target_properties(crypto_demo node_app PROPERTIES
        BUILD_RPATH "${FROST_RUST_LIB}"
        INSTALL_RPATH "${FROST_RUST_LIB}"
    )
endif()