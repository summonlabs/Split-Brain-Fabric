# Test suites.
#
# No test carries a timeout: a hanging test is a defect to diagnose, so ctest is
# configured without TIMEOUT properties and no suite installs a watchdog.

set(SBF_TEST_SUPPORT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/support")

function(sbf_add_test name)
  add_executable(${name} ${ARGN})
  target_include_directories(${name} PRIVATE "${SBF_TEST_SUPPORT_DIR}")
  sbf_configure_executable(${name})
  if(NOT MSVC)
    find_package(Threads REQUIRED)
    target_link_libraries(${name} PRIVATE Threads::Threads)
  endif()
  add_test(NAME ${name} COMMAND ${name})
endfunction()

sbf_add_test(sbf-test-unit-core unit_core.cpp)
sbf_add_test(sbf-test-codec-protocol codec_protocol.cpp)
sbf_add_test(sbf-test-unit-arbiter unit_arbiter.cpp)
sbf_add_test(sbf-test-unit-selection unit_selection.cpp)
sbf_add_test(sbf-test-persistence persistence_adversarial.cpp)
sbf_add_test(sbf-test-integration integration_services.cpp)
sbf_add_test(sbf-test-adversarial adversarial_state.cpp)
sbf_add_test(sbf-test-concurrency concurrency_lifecycle.cpp)
sbf_add_test(sbf-test-scale scale_benchmark.cpp)

if(SBF_BUILD_TOOLS)
  sbf_add_test(sbf-test-multiprocess multiprocess_split_brain.cpp)
  target_compile_definitions(sbf-test-multiprocess PRIVATE
    SBF_REGISTRY_EXE="$<TARGET_FILE:sbf-registry>"
    SBF_WITNESS_EXE="$<TARGET_FILE:sbf-witness>"
    SBF_COORDINATOR_EXE="$<TARGET_FILE:sbf-coordinator>"
    SBF_CTL_EXE="$<TARGET_FILE:sbfctl>")
endif()

# Downstream consumer: an independent CMake project outside this source tree that
# finds the installed package, links the exported target and runs.
# The consumer configure needs the same toolchain as the parent build. When the
# test is run from an environment without the compiler on PATH (a bare ctest
# invocation), the compiler path is forwarded explicitly.
add_test(NAME sbf-test-install-consumer
  COMMAND ${CMAKE_COMMAND}
    -DSBF_SOURCE_DIR=${CMAKE_SOURCE_DIR}
    -DSBF_BINARY_DIR=${CMAKE_BINARY_DIR}
    -DSBF_CONFIG=$<CONFIG>
    -DSBF_GENERATOR=${CMAKE_GENERATOR}
    -DSBF_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DSBF_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DSBF_EXPECT_TOOLS=${SBF_BUILD_TOOLS}
    -P "${CMAKE_CURRENT_SOURCE_DIR}/install_consumer/run_consumer_test.cmake")
