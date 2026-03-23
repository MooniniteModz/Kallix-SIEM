cmake_minimum_required(VERSION 3.20)
project(outpost VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Options ──
option(OUTPOST_BUILD_TESTS "Build test suite" ON)

# ── FetchContent Dependencies ──
include(FetchContent)

# nlohmann/json - JSON parsing
FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)

# spdlog - structured logging
FetchContent_Declare(spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.14.1
    GIT_SHALLOW    TRUE
)

# yaml-cpp - config and rule parsing
FetchContent_Declare(yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
    GIT_TAG        0.8.0
    GIT_SHALLOW    TRUE
)

# cpp-httplib - HTTP server + client
FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG        v0.16.3
    GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(json spdlog yaml-cpp httplib)

# ── OpenSSL (for HTTPS in http_poller) ──
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    message(STATUS "OpenSSL found: HTTPS support enabled")
else()
    message(WARNING "OpenSSL not found: HTTPS support disabled (M365/Azure pollers will not work)")
endif()

# ── PostgreSQL (libpq) ──
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBPQ REQUIRED libpq)

add_library(libpq_wrapper INTERFACE)
target_include_directories(libpq_wrapper INTERFACE ${LIBPQ_INCLUDE_DIRS})
target_link_libraries(libpq_wrapper INTERFACE ${LIBPQ_LIBRARIES})

# ── Outpost Library (shared across binary and tests) ──
add_library(outpost_lib STATIC
    src/common/event.cpp
    src/common/logger.cpp
    src/common/utils.cpp
    src/ingestion/syslog_listener.cpp
    src/ingestion/ring_buffer.cpp
    src/ingestion/http_poller.cpp
    src/parser/fortigate_parser.cpp
    src/parser/syslog_parser.cpp
    src/parser/windows_parser.cpp
    src/parser/m365_parser.cpp
    src/parser/azure_parser.cpp
    src/storage/postgres_storage_engine.cpp
    src/storage/retention.cpp
    src/rules/rule.cpp
    src/rules/rule_engine.cpp
    src/api/server.cpp
    src/auth/auth.cpp
)

target_include_directories(outpost_lib PUBLIC src)
target_link_libraries(outpost_lib PUBLIC
    nlohmann_json::nlohmann_json
    spdlog::spdlog
    yaml-cpp::yaml-cpp
    httplib::httplib
    libpq_wrapper
    pthread
)

if(OPENSSL_FOUND)
    target_link_libraries(outpost_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(outpost_lib PUBLIC CPPHTTPLIB_OPENSSL_SUPPORT)
endif()

# ── Main Binary ──
add_executable(outpost src/main.cpp)
target_link_libraries(outpost PRIVATE outpost_lib)

# ── Tests ──
if(OUTPOST_BUILD_TESTS)
    enable_testing()
    FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(googletest)

    add_executable(outpost_tests
        tests/test_ring_buffer.cpp
        tests/test_parsers.cpp
        tests/test_storage.cpp
        tests/test_rules.cpp
    )
    target_link_libraries(outpost_tests PRIVATE outpost_lib GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(outpost_tests)

    # ── Data injector tool (for testing/demo) ──
    add_executable(inject_events tests/test_inject_events.cpp)
    target_link_libraries(inject_events PRIVATE outpost_lib)
endif()
