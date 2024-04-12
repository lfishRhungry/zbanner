cmake_minimum_required(VERSION 3.20)
project(xtate VERSION 0.9)

if (NOT CMAKE_BUILD_TYPE)
   set (CMAKE_BUILD_TYPE "Release")
   message (
      STATUS "No CMAKE_BUILD_TYPE selected, defaulting to ${CMAKE_BUILD_TYPE}"
   )
endif ()

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(exe_name "xtate_debug")
else (${CMAKE_BUILD_TYPE} STREQUAL "Release")
    set(exe_name "xtate")
endif ()

add_executable(${exe_name})

file(GLOB_RECURSE sources CONFIGURE_DEPENDS src/*.c src/*.h)
target_sources(${exe_name} PUBLIC ${sources})

# openssl
# set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
target_link_libraries(${exe_name} OpenSSL::Crypto OpenSSL::SSL)

# pcre2
# set(PCRE2_USE_STATIC_LIBS ON)
find_package(PCRE2 REQUIRED CONFIG COMPONENTS 8BIT)
target_link_libraries(${exe_name} PCRE2::8BIT)

# math
target_link_libraries(${exe_name} m)