# Installs the project into a scratch prefix, then configures, builds and runs an
# independent downstream consumer against that installation.
#
# Invoked by ctest; there are no timeouts and no sleeps.

if(NOT DEFINED SBF_SOURCE_DIR OR NOT DEFINED SBF_BINARY_DIR)
  message(FATAL_ERROR "SBF_SOURCE_DIR and SBF_BINARY_DIR are required")
endif()
if(NOT DEFINED SBF_CONFIG OR SBF_CONFIG STREQUAL "")
  set(SBF_CONFIG Release)
endif()

set(work "${SBF_BINARY_DIR}/install-consumer-test")
set(prefix "${work}/prefix")
set(build "${work}/consumer-build")
file(REMOVE_RECURSE "${work}")
file(MAKE_DIRECTORY "${work}")

set(install_command "${CMAKE_COMMAND}" --install "${SBF_BINARY_DIR}" --prefix "${prefix}")
if(NOT SBF_CONFIG STREQUAL "")
  list(APPEND install_command --config "${SBF_CONFIG}")
endif()
execute_process(COMMAND ${install_command} RESULT_VARIABLE install_result
                OUTPUT_VARIABLE install_output ERROR_VARIABLE install_output)
if(NOT install_result EQUAL 0)
  message(FATAL_ERROR "cmake --install failed (${install_result}):\n${install_output}")
endif()
message(STATUS "installed prefix: ${prefix}")

# The consumer must be able to find the package purely from the prefix.
set(configure_command "${CMAKE_COMMAND}"
  -S "${SBF_SOURCE_DIR}/tests/install_consumer"
  -B "${build}"
  "-DCMAKE_PREFIX_PATH=${prefix}"
  "-DCMAKE_BUILD_TYPE=${SBF_CONFIG}")
if(DEFINED SBF_GENERATOR AND NOT SBF_GENERATOR STREQUAL "")
  list(APPEND configure_command -G "${SBF_GENERATOR}")
endif()
if(DEFINED SBF_CXX_COMPILER AND NOT SBF_CXX_COMPILER STREQUAL "")
  list(APPEND configure_command "-DCMAKE_CXX_COMPILER=${SBF_CXX_COMPILER}")
endif()
execute_process(COMMAND ${configure_command} RESULT_VARIABLE configure_result
                OUTPUT_VARIABLE configure_output ERROR_VARIABLE configure_output)
if(NOT configure_result EQUAL 0)
  message(FATAL_ERROR "consumer configure failed (${configure_result}):\n${configure_output}")
endif()

execute_process(COMMAND "${CMAKE_COMMAND}" --build "${build}" --config "${SBF_CONFIG}"
                RESULT_VARIABLE build_result OUTPUT_VARIABLE build_output
                ERROR_VARIABLE build_output)
if(NOT build_result EQUAL 0)
  message(FATAL_ERROR "consumer build failed (${build_result}):\n${build_output}")
endif()

set(consumer "${build}/sbf-consumer")
if(WIN32)
  set(consumer "${consumer}.exe")
endif()
if(NOT EXISTS "${consumer}")
  message(FATAL_ERROR "consumer executable not found at ${consumer}")
endif()

execute_process(COMMAND "${consumer}" RESULT_VARIABLE run_result
                OUTPUT_VARIABLE run_output ERROR_VARIABLE run_output)
message(STATUS "consumer output: ${run_output}")
if(NOT run_result EQUAL 0)
  message(FATAL_ERROR "consumer run failed (${run_result}):\n${run_output}")
endif()

# The installed package must also export the tools and the public headers.
foreach(header arbiter.hpp audit.hpp authority.hpp canonical.hpp clock.hpp coordinator.hpp
               digest.hpp evidence.hpp fabric_store.hpp fence.hpp ids.hpp lineage.hpp limits.hpp
               net.hpp persistence.hpp protocol.hpp reconcile.hpp registry.hpp scope.hpp
               status.hpp text.hpp version.hpp version_generated.hpp witness.hpp)
  if(NOT EXISTS "${prefix}/include/sbf/${header}")
    message(FATAL_ERROR "installed header missing: ${header}")
  endif()
endforeach()
if(NOT DEFINED SBF_EXPECT_TOOLS OR SBF_EXPECT_TOOLS)
  foreach(tool sbfctl sbf-registry sbf-witness sbf-coordinator)
    set(candidate "${prefix}/bin/${tool}")
    if(WIN32)
      set(candidate "${candidate}.exe")
    endif()
    if(NOT EXISTS "${candidate}")
      message(FATAL_ERROR "installed tool missing: ${tool}")
    endif()
  endforeach()
endif()

message(STATUS "install + downstream consumer: OK")
