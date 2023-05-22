#*******************************************************************************
# This file is part of MADCAT, the Mass Attack Detection Acceptance Tool.
#    MADCAT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#    MADCAT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#    You should have received a copy of the GNU General Public License
#    along with MADCAT.  If not, see <http://www.gnu.org/licenses/>.
#
# Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
#    MADCAT ist Freie Software: Sie können es unter den Bedingungen
#    der GNU General Public License, wie von der Free Software Foundation,
#    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
#    veröffentlichten Version, weiter verteilen und/oder modifizieren.
#    MADCAT wird in der Hoffnung, dass es nützlich sein wird, aber
#    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
#    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
#    Siehe die GNU General Public License für weitere Details.
#    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
#    Programm erhalten haben. Wenn nicht, siehe <https://www.gnu.org/licenses/>.
#*******************************************************************************/
#
#BSI 2020-2021
#

project(MADCAT)
cmake_minimum_required(VERSION 2.8...3.13)
set (VERSION 2.3.1)

#Common project parameter
set(PACKAGE_NAME MADCAT)
set(PACKAGE_VERSION "${VERSION}")
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(UNINSTALL_SCRIPT "uninstall.sh")

#Select the arch
if(CMAKE_TARGET STREQUAL "aarch64")

  message(STATUS "checking cross compile environment")
  set(CMAKE_SYSTEM_NAME Linux)
  set(CMAKE_SYSTEM_PROCESSOR aarch64)
  #set(CMAKE_CROSSCOMPILING true)

  set(CMAKE_SYSROOT /usr/aarch64-linux-gnu)
  set(CMAKE_C_COMPILER /usr/bin/aarch64-linux-gnu-gcc)
  set(CMAKE_FIND_ROOT_PATH /usr/aarch64-linux-gnu)

  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

  set(OPENSSL_ROOT_DIR /usr/aarch64-linux-gnu)
  set(OPENSSL_CRYPTO_LIBRARY /usr/aarch64-linux-gnu/lib/libcrypto.so)
  set(OPENSSL_SSL_LIBRARY /usr/aarch64-linux-gnu/lib/libssl.so)
  set(OPENSSL_INCLUDE_DIR /usr/aarch64-linux-gnu/include)

  find_package(OpenSSL REQUIRED)
  message(STATUS "Found OpenSSL ${OPENSSL_VERSION} for ${CMAKE_SYSTEM_PROCESSOR} architecture (${OPENSSL_CRYPTO_LIBRARY}, ${OPENSSL_LIBRARY})")

  set(PCAP_ROOT_DIR /usr/aarch64-linux-gnu )
  set(PCAP_LIBRARY /usr/aarch64-linux-gnu/lib/libpcap.so)
  set(PCAP_INCLUDE_DIR /usr/aarch64-linux-gnu/include)
  MARK_AS_ADVANCED(PCAP_LIBRARY)
  message(STATUS "Found PCAP ${PCAP_ROOT_DIR} for ${CMAKE_SYSTEM_PROCESSOR} architecture")

  SET(LUA_INCLUDE_DIR /usr/aarch64-linux-gnu/include)
  SET(LUA_LIBRARIES /usr/aarch64-linux-gnu )
  SET(LUA_LIBRARY /usr/aarch64-linux-gnu/lib/liblua5.1.so)
  MARK_AS_ADVANCED(LUA_INCLUDE_DIR)
  MARK_AS_ADVANCED(LUA_LIBRARIES)
  MARK_AS_ADVANCED(LUA_LIBRARY)
  message(STATUS "Found LUA ${LUA_LIBRARIES} for ${CMAKE_SYSTEM_PROCESSOR} architecture")    

  # thread library
  set(CMAKE_THREAD_LIBS_INIT "-lpthread")
  set(CMAKE_HAVE_THREADS_LIBRARY 1)
  set(CMAKE_USE_WIN32_THREADS_INIT 0)
  set(CMAKE_USE_PTHREADS_INIT 1)
  set(THREADS_PREFER_PTHREAD_FLAG ON) 
  find_package(Threads REQUIRED)

elseif(CMAKE_TARGET STREQUAL "armhf")
  message(STATUS "checking cross compile environment")
  set(CMAKE_SYSTEM_NAME Linux)
  set(CMAKE_SYSTEM_PROCESSOR arm)
  #set(CMAKE_CROSSCOMPILING true)

  set(CMAKE_SYSROOT /usr/arm-linux-gnueabihf)
  set(CMAKE_C_COMPILER /usr/bin/arm-linux-gnueabihf-gcc)           
  set(CMAKE_FIND_ROOT_PATH /usr/arm-linux-gnueabihf)                                             

  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

  set(OPENSSL_ROOT_DIR /usr/arm-linux-gnueabihf )
  set(OPENSSL_CRYPTO_LIBRARY /usr/arm-linux-gnueabihf/lib/libcrypto.so)
  set(OPENSSL_SSL_LIBRARY /usr/arm-linux-gnueabihf/lib/libssl.so)
  set(OPENSSL_INCLUDE_DIR /usr/arm-linux-gnueabihf/include)
  
  find_package(OpenSSL REQUIRED)
  message(STATUS "Found OpenSSL ${OPENSSL_VERSION} for ${CMAKE_SYSTEM_PROCESSOR} architecture")

  set(PCAP_ROOT_DIR /usr/arm-linux-gnueabihf )
  set(PCAP_LIBRARY /usr/arm-linux-gnueabihf/lib/libpcap.so)
  set(PCAP_INCLUDE_DIR /usr/arm-linux-gnueabihf/include)
  MARK_AS_ADVANCED(PCAP_LIBRARY)
  message(STATUS "Found PCAP ${PCAP_ROOT_DIR} for ${CMAKE_SYSTEM_PROCESSOR} architecture")

  SET(LUA_INCLUDE_DIR /usr/arm-linux-gnueabihf/include)
  SET(LUA_LIBRARIES /usr/arm-linux-gnueabihf )
  SET(LUA_LIBRARY /usr/arm-linux-gnueabihf/lib/liblua5.1.so)
  MARK_AS_ADVANCED(LUA_INCLUDE_DIR)
  MARK_AS_ADVANCED(LUA_LIBRARIES)
  MARK_AS_ADVANCED(LUA_LIBRARY)
  message(STATUS "Found LUA ${LUA_LIBRARIES} for ${CMAKE_SYSTEM_PROCESSOR} architecture")    
  
  # thread library
  set(CMAKE_THREAD_LIBS_INIT "-lpthread")
  set(CMAKE_HAVE_THREADS_LIBRARY 1)
  set(CMAKE_USE_WIN32_THREADS_INIT 0)
  set(CMAKE_USE_PTHREADS_INIT 1)
  set(THREADS_PREFER_PTHREAD_FLAG ON) 
  find_package(Threads REQUIRED)

elseif(CMAKE_TARGET STREQUAL "x86_64")

  set(CMAKE_SYSTEM_NAME Linux)
  
  # Add CMake config files to build env
  list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

  # looking for dependencies
  # OpenSSL
  find_package(OpenSSL REQUIRED)
  # PCAP Library
  find_package(PCAP REQUIRED)
  # Lua Library
  find_package(Lua51 REQUIRED)
  # thread library
  set(CMAKE_THREAD_LIBS_INIT "-lpthread")
  set(CMAKE_HAVE_THREADS_LIBRARY 1)
  set(CMAKE_USE_WIN32_THREADS_INIT 0)
  set(CMAKE_USE_PTHREADS_INIT 1)
  set(THREADS_PREFER_PTHREAD_FLAG ON) 
  find_package(Threads REQUIRED)

else()
  set(CMAKE_SYSTEM_NAME Linux)
  set(CMAKE_TARGET "x86_64")
  # Add CMake config files to build env
  list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

  # looking for dependencies
  # OpenSSL
  find_package(OpenSSL REQUIRED)
  # PCAP Library
  find_package(PCAP REQUIRED)
  # Lua Library
  find_package(Lua51 REQUIRED)
  # thread library
  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
  # netfilter_conntrack library
  SET(NFCT_INCLUDE_DIR /usr/include/libnetfilter_conntrack)
  SET(NFCT_LIBRARIES /usr/lib/x86_64-linux-gnu/)
  SET(NFCT_LIBRARY /usr/lib/x86_64-linux-gnu/libnetfilter_conntrack.so) 

endif()

message(STATUS "Architecture: ${CMAKE_SYSTEM_NAME} ${CMAKE_SYSTEM_PROCESSOR}")

# Common C_FLAG option
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall ")

# Add CAMKE Compile Options
# enable Debugging
if(CMAKE_DEBUG)
  message(STATUS "Enable debugging")
  #-gdwarf-2 geht bei Google-Test net
  set(CMAKE_BUILD_TYPE Debug)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -Wall -fno-strict-aliasing")
endif()

if(CMAKE_FUZZ)
  message(STATUS "Enable fuzzing")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -fsanitize=address,fuzzer-no-link,undefined,signed-integer-overflow,bool,pointer-overflow -fno-omit-frame-pointer  -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -fsanitize=address,fuzzer-no-link,undefined,signed-integer-overflow,bool,pointer-overflow -fno-omit-frame-pointer  -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep")
  option(MADCAT_FUZZ "Enable fuzzing building" ON)
endif()

if(CMAKE_USE_ASAN)
  message(STATUS "Enable address sanitizer")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
endif()

if(CMAKE_VERBOSE)
  message(STATUS "Enable more output")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -v")
endif()

if(CMAKE_TESTS)
  message(STATUS "Enable tests")
  option(MADCAT_TEST "Enable tests building" ON)
endif()

message(STATUS "C Flags: ${CMAKE_C_FLAGS}")

# Set directory for libraries and executables
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/lib")

# if test enable
if(MADCAT_TEST)
  # Google Test
  # Download and unpack googletest at configure time
  configure_file(cmake/CreateGoogleTestENV.txt.in googletest-download/CMakeLists.txt)

  execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/googletest-download )
  if(result)
    message(FATAL_ERROR "CMake step for googletest failed: ${result}")
  endif()
  execute_process(COMMAND ${CMAKE_COMMAND} --build .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/googletest-download )
  if(result)
    message(FATAL_ERROR "Build step for googletest failed: ${result}")
  endif()

  # Prevent overriding the parent project's compiler/linker
  # settings on Windows
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

  # Add googletest directly to our build. This defines
  # the gtest and gtest_main targets.
  add_subdirectory(${CMAKE_BINARY_DIR}/googletest-src
                  ${CMAKE_BINARY_DIR}/googletest-build
                  EXCLUDE_FROM_ALL)

  # The gtest/gtest_main targets carry header search path
  # dependencies automatically when using CMake 2.8.11 or
  # later. Otherwise, we have to add them here ourselves.
  if (CMAKE_VERSION VERSION_LESS 2.8.11)
    include_directories("${gtest_SOURCE_DIR}/include")
  endif()

  # Now simply link your own targets against gtest, gmock,
  # etc. as appropriate
endif()

############## GENERATE UNINSTALL SCRIPT #################
execute_process(
  COMMAND touch ${UNINSTALL_SCRIPT}
  COMMAND bash -c "echo \"\#\!/bin/bash\ncat install_manifest.txt | sudo xargs rm -v\necho \"done ...\"\n \" > ${UNINSTALL_SCRIPT}"
  COMMAND bash -c "chmod u+x ${UNINSTALL_SCRIPT}"
)

############## FINAL PROJECT CONFIG #################
# And the project header and library paths
# case distinction between arm and x86 
if(CMAKE_TARGET STREQUAL "aarch64")
 
  include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/rsp
    ${CMAKE_SOURCE_DIR}/include/dict_c
    ${LUA_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
  )

elseif(CMAKE_TARGET STREQUAL "armhf")
  
  include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/rsp
    ${CMAKE_SOURCE_DIR}/include/dict_c
    ${LUA_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
    ${PCAP_INCLUDE_DIR}
  )

elseif(CMAKE_TARGET STREQUAL "x86_64")

  include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/rsp
    ${CMAKE_SOURCE_DIR}/include/dict_c
    ${LUA_INCLUDE_DIR}
    ${NFCT_INCLUDE_DIR}
  )

endif()


# include folder lib, bin
add_subdirectory(lib)
add_subdirectory(bin)

if(MADCAT_TEST)
  enable_testing()
  add_subdirectory(tests)
endif()

if(MADCAT_FUZZ)
  add_subdirectory(fuzzing)
endif()

