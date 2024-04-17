cmake_minimum_required(VERSION 3.20)
project(xtate VERSION 0.9)

if (NOT CMAKE_BUILD_TYPE)
   set (CMAKE_BUILD_TYPE "Release")
   message (
      STATUS "No CMAKE_BUILD_TYPE selected, defaulting to ${CMAKE_BUILD_TYPE}"
   )
endif ()

if (UNIX)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -O0 -rdynamic -ggdb -no-pie")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -Wall")
endif ()

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(exe_name "xtate_debug")
else ()
    set(exe_name "xtate")
endif ()

add_executable(${exe_name})

file(GLOB_RECURSE sources CONFIGURE_DEPENDS src/*.c src/*.h)
target_sources(${exe_name} PUBLIC ${sources})

# find_package(Threads REQUIRED)
# target_link_libraries(${exe_name} Threads::Threads)

# openssl
# set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
target_link_libraries(${exe_name} OpenSSL::Crypto OpenSSL::SSL)

# pcre2
# set(PCRE2_USE_STATIC_LIBS TRUE)
find_package(PCRE2 REQUIRED CONFIG COMPONENTS 8BIT)
target_link_libraries(${exe_name} PCRE2::8BIT)

# lua5.3
# set(LUA_USE_STATIC_LIBS TRUE)
find_package(Lua REQUIRED)
target_include_directories(${exe_name} PRIVATE ${LUA_INCLUDE_DIR})
target_link_libraries(${exe_name} ${LUA_LIBRARIES})

# math
if (UNIX)
    target_link_libraries(${exe_name} m)
endif ()