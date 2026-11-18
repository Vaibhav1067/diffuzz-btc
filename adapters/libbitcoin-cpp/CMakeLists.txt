cmake_minimum_required(VERSION 3.30)
project(diffuzz-adapter-libbitcoin CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LIBBITCOIN_PIN "unknown" CACHE STRING "libbitcoin-system tag the adapter is built against")

find_package(libbitcoin-system REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(diffuzz-adapter-libbitcoin main.cpp)
target_compile_definitions(diffuzz-adapter-libbitcoin PRIVATE LIBBITCOIN_PIN="${LIBBITCOIN_PIN}")
target_link_libraries(diffuzz-adapter-libbitcoin PRIVATE bitcoin::system nlohmann_json::nlohmann_json)
