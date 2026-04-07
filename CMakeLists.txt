cmake_minimum_required(VERSION 3.20)
project(TimestampNetwork)

set(CMAKE_CXX_STANDARD 17)

# Mac homebrew dependencies
if(APPLE)
    list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew")
    include_directories(/opt/homebrew/include)
endif()

find_package(OpenSSL REQUIRED)
find_library(SODIUM_LIB NAMES sodium PATHS /opt/homebrew/lib /usr/local/lib REQUIRED)

include_directories(include)
include_directories(lib)
include_directories(${OPENSSL_INCLUDE_DIR})

# Fetch GoogleTest
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# Prevent overriding the parent project's compiler/linker settings (for Windows)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Rust library setup
if(APPLE)
    set(LIB_EXT "dylib")
else()
    set(LIB_EXT "so")
endif()
set(FROST_RUST_LIB ${CMAKE_SOURCE_DIR}/lib/frostdemo/target/release)

set(COMMON_LIBS
        ${FROST_RUST_LIB}/libfrostdemo.${LIB_EXT}
        ${OPENSSL_LIBRARIES}
        ${SODIUM_LIB}
        dl
        pthread
)

add_executable(keygen
    src/keygen_main.cpp
    src/keygen.cpp
)

add_executable(verify_cli
    src/verify_cli.cpp
    src/base64.cpp
)

add_executable(client_cli
    src/client_cli.cpp
    src/base64.cpp
    src/crypto_utils.cpp
)

add_executable(server_main
    src/server_main.cpp
    src/base64.cpp
    src/crypto_utils.cpp
)

# Link all executables
target_link_libraries(keygen ${COMMON_LIBS})
target_link_libraries(verify_cli ${COMMON_LIBS})
target_link_libraries(server_main ${COMMON_LIBS})
target_link_libraries(client_cli ${COMMON_LIBS})

# Test executable
enable_testing()

add_executable(unit_tests
    tests/test_base64.cpp
    src/base64.cpp
)

# Link GTest
target_link_libraries(unit_tests GTest::gtest_main GTest::gtest)
target_include_directories(unit_tests PRIVATE include)

# Register the test
include(GoogleTest)
gtest_discover_tests(unit_tests)

# RPATH for Rust shared library
if(APPLE)
    set_target_properties(server_main keygen verify_cli client_cli unit_tests PROPERTIES
            INSTALL_RPATH "@loader_path/../lib/frostdemo/target/release"
            BUILD_WITH_INSTALL_RPATH TRUE
    )
else()
    set_target_properties(server_main keygen verify_cli client_cli unit_tests PROPERTIES
            BUILD_RPATH "${FROST_RUST_LIB}"
            INSTALL_RPATH "${FROST_RUST_LIB}"
    )
endif()