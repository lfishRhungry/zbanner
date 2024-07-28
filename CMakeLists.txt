cmake_minimum_required(VERSION 3.20)
project(
    xtate
    LANGUAGES               C
    VERSION                 1.1.3
    DESCRIPTION             "A modular all-stack network scanner for next-generation internet surveys."
    HOMEPAGE_URL            "https://github.com/sharkocha/xtate"
    )
set(PROJECT_NAME_ALL_CAPS   "XTATE")
set(PROJECT_NAME_TITLE_CASE "Xtate")
set(PROJECT_AUTHOR          "Sharkocha")
set(PROJECT_CONTACT         "chenchiyu14@nudt.edu.cn")
set(PROJECT_GITHUB_URL      "https://github.com/sharkocha/xtate")
set(PROJECT_ISSUES_URL      "https://github.com/sharkocha/xtate/issues")
set(PROJECT_CONF_PATH       "/etc/xtate/xtate.conf")
set(PROJECT_BANNER          "God is Stateless")

configure_file(${CMAKE_SOURCE_DIR}/src/version.h.in ${CMAKE_SOURCE_DIR}/src/version.h @ONLY)



option(WITH_OPENSSL        "Build with OpenSSL library"                   ON)
option(WITH_PCRE2          "Build with PCRE2 library"                     ON)
option(WITH_LIBXML2        "Build with LibXml2 library"                   ON)
option(WITH_JUDY           "Build with Judy library"                      ON)
# option(WITH_FANN           "Build with Fann library"                      ON)

# According to C99 standards while using designated initializer:
#     "Omitted fields are implicitly initialized the same as for objects
# that have static storage duration."
#
# ref: https://gcc.gnu.org/onlinedocs/gcc/Designated-Inits.html
#
# This is more efficient to got an all-zero var than memset and could got
# a partial-zero var conveniently.
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

if (NOT CMAKE_BUILD_TYPE)
   set (CMAKE_BUILD_TYPE "Release")
   message (
      STATUS "No CMAKE_BUILD_TYPE selected, defaulting to ${CMAKE_BUILD_TYPE}"
   )
endif ()

if (UNIX OR MINGW)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -O0 -ggdb -fno-pie")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -Wall -DNDEBUG")
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_link_options(-no-pie)
        if (NOT MINGW)
            add_link_options(-rdynamic)
        endif ()
    endif ()
endif ()

if (${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(exe_name "xtate_debug")
else ()
    set(exe_name "xtate")
endif ()

add_executable(${exe_name})

file(GLOB_RECURSE sources CONFIGURE_DEPENDS src/*.c src/*.h)
target_sources(${exe_name} PUBLIC ${sources})

# Unix--------------------math(libm) libdl pthread
if (UNIX)
    target_link_libraries(${exe_name} m)
    target_link_libraries(${exe_name} ${CMAKE_DL_LIBS})
    # target_link_libraries(${exe_name} rt)
    find_package(Threads REQUIRED)
    target_link_libraries(${exe_name} Threads::Threads)
endif ()


# Windows--------------------WSock iphlpAPI
if (WIN32)
    target_link_libraries(${exe_name} wsock32 ws2_32)
    target_link_libraries(${exe_name} IPHLPAPI.lib)
endif ()


# --------------------openssl
if (${WITH_OPENSSL})
    # set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL 1.1.1)
endif ()

if (${OPENSSL_FOUND})
    #include_directories(${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${exe_name} OpenSSL::Crypto OpenSSL::SSL)
else ()
    add_compile_definitions(NOT_FOUND_OPENSSL)
endif ()


# --------------------pcre2
if (${WITH_PCRE2})
    # set(PCRE2_USE_STATIC_LIBS TRUE)
    find_package(PCRE2 CONFIG COMPONENTS 8BIT)
endif ()

if (${PCRE2_FOUND})
    target_link_libraries(${exe_name} PCRE2::8BIT)
else ()
    add_compile_definitions(NOT_FOUND_PCRE2)
endif ()


# --------------------libxml2
if (${WITH_LIBXML2})
    # set(LIBXML2_USE_STATIC_LIBS TRUE)
    find_package(LibXml2)
endif ()

if (${LibXml2_FOUND})
    #include_directories(${LIBXML2_INCLUDE_DIR})
    target_link_libraries(${exe_name} LibXml2::LibXml2)
else ()
    add_compile_definitions(NOT_FOUND_LIBXML2)
endif ()


# --------------------libjudy
if (${WITH_JUDY})
    find_library(FOUND_JUDY HINTS /usr/include/ NAMES Judy libjudy-dev judy dev-libs/judy judy-devel)
endif ()

if (FOUND_JUDY)
    #include_directories(${LIBXML2_INCLUDE_DIR})
    target_link_libraries(${exe_name} Judy)
else ()
    add_compile_definitions(NOT_FOUND_JUDY)
endif ()

# --------------------fann
# if (${WITH_FANN})
#     find_package(fann)
# endif ()

# if (${fann_FOUND})
#     target_link_libraries(${exe_name} fann)
# else ()
#     add_compile_definitions(NOT_FOUND_FANN)
# endif ()

# --------------------lua5.3
# set(LUA_USE_STATIC_LIBS TRUE)
# find_package(Lua REQUIRED)
# target_include_directories(${exe_name} PRIVATE ${LUA_INCLUDE_DIR})
# target_link_libraries(${exe_name} ${LUA_LIBRARIES})