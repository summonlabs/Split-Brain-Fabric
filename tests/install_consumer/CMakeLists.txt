cmake_minimum_required(VERSION 3.20)

# Independent downstream consumer. This project lives outside the Split-Brain
# Fabric source tree's build system entirely: it consumes only the installed
# CMake package, exactly as a third party would.

project(SbfConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(SplitBrainFabric 1.0 CONFIG REQUIRED)

add_executable(sbf-consumer main.cpp)
target_link_libraries(sbf-consumer PRIVATE SplitBrainFabric::sbf)
target_compile_features(sbf-consumer PRIVATE cxx_std_20)
