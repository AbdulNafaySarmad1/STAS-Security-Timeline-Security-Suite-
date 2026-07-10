cmake_minimum_required(VERSION 3.10)
project(STAS)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(STAS_ENABLE_YARA "Enable YARA scanning when libyara is available" ON)
option(STAS_ENABLE_OPENSSL "Enable OpenSSL-backed hashing when implemented" ON)
option(STAS_ENABLE_SQLITE "Enable SQLite event storage when SQLite3 is available" ON)

if(STAS_ENABLE_SQLITE)
    find_package(SQLite3 QUIET)
endif()
find_package(nlohmann_json CONFIG QUIET)

set(STAS_ENGINE_SOURCES
    src/cpp/main.cpp
    src/cpp/static_analysis.cpp
    src/cpp/dynamic_timeline.cpp
    src/cpp/sandbox.cpp
    src/cpp/sqlite_db.cpp
    src/cpp/risk_scoring.cpp
    src/cpp/autorun_detector.cpp
)

if(nlohmann_json_FOUND)
    list(APPEND STAS_ENGINE_SOURCES
        src/cpp/attack_mapper.cpp
        src/cpp/import_profiler.cpp
        src/cpp/ioc_extractor.cpp
    )
else()
    include(CheckIncludeFileCXX)
    check_include_file_cxx("nlohmann/json.hpp" STAS_HAS_NLOHMANN_JSON_HEADER)
    if(STAS_HAS_NLOHMANN_JSON_HEADER)
        list(APPEND STAS_ENGINE_SOURCES
            src/cpp/attack_mapper.cpp
            src/cpp/import_profiler.cpp
            src/cpp/ioc_extractor.cpp
        )
    else()
        message(STATUS "nlohmann/json.hpp not found; JSON-backed ATT&CK, import profile, and IOC exports will be disabled")
    endif()
endif()

add_executable(stas_engine ${STAS_ENGINE_SOURCES})

target_include_directories(stas_engine PRIVATE src/cpp)

if(SQLite3_FOUND)
    target_link_libraries(stas_engine SQLite::SQLite3)
    target_compile_definitions(stas_engine PRIVATE STAS_WITH_SQLITE=1)
else()
    message(STATUS "SQLite3 not found; event storage will use a no-op backend")
endif()

if(nlohmann_json_FOUND)
    target_link_libraries(stas_engine nlohmann_json::nlohmann_json)
    target_compile_definitions(stas_engine PRIVATE STAS_WITH_JSON=1)
elseif(STAS_HAS_NLOHMANN_JSON_HEADER)
    target_compile_definitions(stas_engine PRIVATE STAS_WITH_JSON=1)
endif()

if(STAS_ENABLE_OPENSSL)
    find_package(OpenSSL QUIET)
    if(OpenSSL_FOUND)
        target_link_libraries(stas_engine OpenSSL::SSL OpenSSL::Crypto)
        target_compile_definitions(stas_engine PRIVATE STAS_WITH_OPENSSL=1)
    else()
        message(STATUS "OpenSSL not found; hashing placeholders will build without OpenSSL")
    endif()
endif()

if(STAS_ENABLE_YARA)
    find_package(unofficial-libyara CONFIG QUIET)
    if(unofficial-libyara_FOUND)
        target_link_libraries(stas_engine unofficial::libyara::libyara)
        target_compile_definitions(stas_engine PRIVATE STAS_WITH_YARA=1)
    else()
        find_path(YARA_INCLUDE_DIR yara.h)
        find_library(YARA_LIBRARY yara)
        if(YARA_INCLUDE_DIR AND YARA_LIBRARY)
            target_include_directories(stas_engine PRIVATE ${YARA_INCLUDE_DIR})
            target_link_libraries(stas_engine ${YARA_LIBRARY})
            target_compile_definitions(stas_engine PRIVATE STAS_WITH_YARA=1)
        else()
            message(STATUS "libyara not found; YARA scanning will be disabled")
        endif()
    endif()
endif()

if(WIN32)
    target_compile_definitions(stas_engine PRIVATE STAS_PLATFORM_WINDOWS=1)
else()
    target_compile_definitions(stas_engine PRIVATE STAS_PLATFORM_POSIX=1)
endif()
