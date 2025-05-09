cmake_minimum_required(VERSION 3.20)
project(vpn)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Always build static binaries
set(BUILD_SHARED_LIBS OFF)

# On MSVC: use the static CRT
if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif ()


# Required for finding Conan packages
find_package(EASTL REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(vpn
        src/main.cpp
        src/include/applink.c
        src/vpn.cpp
)

# Tell OpenSSL headers we're linking them statically 
target_compile_definitions(vpn PRIVATE
        OPENSSL_STATIC
        STATIC_BUILD
)

# Includes
target_include_directories(vpn PRIVATE
        ${OPENSSL_INCLUDE_DIR}
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/include
)

# Link against the static .lib's, not DLL import libs
target_link_libraries(vpn PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ws2_32
        ole32
        iphlpapi
        crypt32      # <-- CryptoAPI
        advapi32     # <-- sometimes needed by CAPI
        EASTL::EASTL
)

# Enable static linking for Windows runtime
if (MSVC)
    foreach (flag_var
            CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
            CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        if (${flag_var} MATCHES "/MD")
            string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif ()
    endforeach ()
endif ()

# Embed a manifest so the EXE auto-elevates on Windows 
set(EXE_MANIFEST "${CMAKE_SOURCE_DIR}/vpn.exe.manifest")
# Mark the manifest as a resource file
set_source_files_properties(${EXE_MANIFEST} PROPERTIES HEADER_FILE_ONLY TRUE)

# Look for mt.exe in common Windows SDK paths
find_program(MT_EXECUTABLE mt
        PATHS
        "C:/Program Files (x86)/Windows Kits/10/bin/10.0.22000.0/x64"
        "C:/Program Files (x86)/Windows Kits/10/bin/10.0.19041.0/x64"
        "C:/Program Files (x86)/Windows Kits/10/bin/10.0.18362.0/x64"
        "C:/Program Files (x86)/Windows Kits/10/bin/x64"
        "C:/Program Files (x86)/Windows Kits/8.1/bin/x64"
)

if (MT_EXECUTABLE)
    # Embed manifest directly into EXE
    add_custom_command(TARGET vpn POST_BUILD
            COMMAND "${MT_EXECUTABLE}"
            -manifest "${CMAKE_SOURCE_DIR}/deps/vpn.exe.manifest"
            "-outputresource:$<TARGET_FILE:vpn>;#1"
            COMMENT "Embedding manifest into EXE with mt.exe"
            VERBATIM
    )
else ()
    # Fallback - copy manifest next to EXE
    add_custom_command(TARGET vpn POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${EXE_MANIFEST}"
            "$<TARGET_FILE_DIR:vpn>/vpn.exe.manifest"
    )
endif ()

# Copy files to build directory
add_custom_command(TARGET vpn POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:vpn>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/deps/wintun.dll"
        "${CMAKE_SOURCE_DIR}/deps/fips.dll"
        "${CMAKE_SOURCE_DIR}/deps/openssl.exe"
        "${CMAKE_SOURCE_DIR}/deps/run_fipsinstall.bat"
        "${CMAKE_SOURCE_DIR}/deps/openssl.cnf"
        "$<TARGET_FILE_DIR:vpn>"
)

if (WIN32)
    target_sources(vpn PRIVATE ${CMAKE_SOURCE_DIR}/src/version.rc)
endif()
