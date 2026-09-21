cmake_minimum_required(VERSION 3.20)

project(SplitBrainFabric
  VERSION 1.0.0
  DESCRIPTION "Split-brain prevention and authority fencing for fabric control domains"
  HOMEPAGE_URL "https://github.com/summonlabs/Split-Brain-Fabric"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(SBF_BUILD_TOOLS "Build the sbf command line tools" ON)
option(SBF_BUILD_EXAMPLES "Build the examples" ON)
option(SBF_BUILD_TESTS "Build the test suite" ON)
option(SBF_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(SBF_ENABLE_SANITIZERS "Enable AddressSanitizer/UBSan when supported" OFF)
option(SBF_ENABLE_IPO "Enable interprocedural optimisation for release builds" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

# Generated version header -----------------------------------------------------
set(SBF_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${SBF_GENERATED_INCLUDE_DIR}/sbf")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.hpp.in"
  "${SBF_GENERATED_INCLUDE_DIR}/sbf/version_generated.hpp"
  @ONLY)

# Library ----------------------------------------------------------------------
add_library(sbf
  src/audit.cpp
  src/arbiter.cpp
  src/authority.cpp
  src/canonical.cpp
  src/clock.cpp
  src/coordinator.cpp
  src/digest.cpp
  src/evidence.cpp
  src/fabric_store.cpp
  src/fence.cpp
  src/ids.cpp
  src/lineage.cpp
  src/audit.cpp
  src/net.cpp
  src/persistence.cpp
  src/protocol.cpp
  src/registry_client.cpp
  src/registry_service.cpp
  src/registry_state.cpp
  src/scope.cpp
  src/selection.cpp
  src/status.cpp
  src/text.cpp
  src/version.cpp
  src/witness_service.cpp
)
add_library(SplitBrainFabric::sbf ALIAS sbf)

target_include_directories(sbf
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<BUILD_INTERFACE:${SBF_GENERATED_INCLUDE_DIR}>"
    "$<INSTALL_INTERFACE:include>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_features(sbf PUBLIC cxx_std_20)

if(MSVC)
  target_compile_options(sbf PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
  if(SBF_WARNINGS_AS_ERRORS)
    target_compile_options(sbf PRIVATE /WX)
  endif()
  target_compile_definitions(sbf PUBLIC _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
  target_link_libraries(sbf PUBLIC ws2_32)
else()
  target_compile_options(sbf PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
  if(SBF_WARNINGS_AS_ERRORS)
    target_compile_options(sbf PRIVATE -Werror)
  endif()
  find_package(Threads REQUIRED)
  target_link_libraries(sbf PUBLIC Threads::Threads)
endif()

if(SBF_ENABLE_SANITIZERS)
  if(MSVC)
    # MSVC ships AddressSanitizer per target architecture. A 32-bit target is
    # built explicitly on hosts where only the i386 runtime is installed.
    target_compile_options(sbf PUBLIC /fsanitize=address /Zi)
    target_link_options(sbf PUBLIC /fsanitize=address)
  else()
    target_compile_options(sbf PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(sbf PUBLIC -fsanitize=address,undefined)
  endif()
endif()

if(SBF_ENABLE_IPO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT SBF_IPO_OK OUTPUT SBF_IPO_MSG)
  if(SBF_IPO_OK)
    set_property(TARGET sbf PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
  else()
    message(STATUS "IPO not supported: ${SBF_IPO_MSG}")
  endif()
endif()

set_target_properties(sbf PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  OUTPUT_NAME "splitbrainfabric")

# Shared internal helper for tool/test targets --------------------------------
function(sbf_configure_executable target)
  target_link_libraries(${target} PRIVATE SplitBrainFabric::sbf)
  target_compile_features(${target} PRIVATE cxx_std_20)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
    if(SBF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
    if(SBF_ENABLE_SANITIZERS)
      target_compile_options(${target} PRIVATE /fsanitize=address /Zi)
      target_link_options(${target} PRIVATE /fsanitize=address)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow)
    if(SBF_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
    if(SBF_ENABLE_SANITIZERS)
      target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
  endif()
endfunction()

if(SBF_BUILD_TOOLS)
  add_executable(sbfctl tools/sbfctl.cpp)
  sbf_configure_executable(sbfctl)

  add_executable(sbf-registry tools/sbf-registry.cpp)
  sbf_configure_executable(sbf-registry)

  add_executable(sbf-witness tools/sbf-witness.cpp)
  sbf_configure_executable(sbf-witness)

  add_executable(sbf-coordinator tools/sbf-coordinator.cpp)
  sbf_configure_executable(sbf-coordinator)
endif()

if(SBF_BUILD_EXAMPLES)
  add_executable(sbf-example-fence examples/fence_cycle.cpp)
  sbf_configure_executable(sbf-example-fence)
endif()

if(SBF_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# Installation -----------------------------------------------------------------
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS sbf
  EXPORT SplitBrainFabricTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(SBF_BUILD_TOOLS)
  install(TARGETS sbfctl sbf-registry sbf-witness sbf-coordinator
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY include/sbf DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES "${SBF_GENERATED_INCLUDE_DIR}/sbf/version_generated.hpp"
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sbf)

install(EXPORT SplitBrainFabricTargets
  FILE SplitBrainFabricTargets.cmake
  NAMESPACE SplitBrainFabric::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SplitBrainFabric)

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/SplitBrainFabricConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/SplitBrainFabricConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SplitBrainFabric)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/SplitBrainFabricConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/SplitBrainFabricConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/SplitBrainFabricConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SplitBrainFabric)

install(FILES LICENSE DESTINATION ${CMAKE_INSTALL_DATADIR}/SplitBrainFabric)
