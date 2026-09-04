cmake_minimum_required(VERSION 3.20)
project(vpn)

# The elevated process verifies the exact bundled Wintun binary before loading
# it. Keep the configure-time package check in sync with src/vpn.cpp so an
# accidental or malicious DLL replacement cannot reach a release artifact.
set(TRUETUNNEL_WINTUN_SHA256
        "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce")
set(TRUETUNNEL_WINTUN_DLL "${CMAKE_SOURCE_DIR}/deps/wintun.dll")
if (NOT EXISTS "${TRUETUNNEL_WINTUN_DLL}")
    message(FATAL_ERROR "Required Wintun runtime is missing: ${TRUETUNNEL_WINTUN_DLL}")
endif ()
file(SHA256 "${TRUETUNNEL_WINTUN_DLL}" TRUETUNNEL_WINTUN_ACTUAL_SHA256)
if (NOT TRUETUNNEL_WINTUN_ACTUAL_SHA256 STREQUAL TRUETUNNEL_WINTUN_SHA256)
    message(FATAL_ERROR
            "deps/wintun.dll does not match the reviewed pinned SHA-256. "
            "Expected ${TRUETUNNEL_WINTUN_SHA256}, got ${TRUETUNNEL_WINTUN_ACTUAL_SHA256}")
endif ()

include(CTest)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Always build static binaries
set(BUILD_SHARED_LIBS OFF)
set(CONAN_CMAKE_FLAGS "--build=missing")
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
option(ENABLE_ANALYSIS "Enable static analysis tools" ON)

if (ENABLE_ANALYSIS)
    find_program(CLANG_TIDY_EXE NAMES clang-tidy)
    if (CLANG_TIDY_EXE)
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_EXE}")
    endif()
endif()

# On MSVC: use the static CRT
if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif ()


# Required for finding Conan packages
find_package(imgui REQUIRED)
find_package(freetype REQUIRED)
set(IMGUI_BACKENDS_DIR "${CMAKE_SOURCE_DIR}/deps/imgui/backends")
set(IMGUI_MISC_DIR "${CMAKE_SOURCE_DIR}/deps/imgui/misc")

# Resolve the exact license files from the Conan package selected for each
# configuration. A single-configuration Conan install may provide only one
# package root, so use it as the fallback for the other configuration.
function(conan_package_license output_variable package_name relative_path)
    set(debug_variable "${package_name}_PACKAGE_FOLDER_DEBUG")
    set(release_variable "${package_name}_PACKAGE_FOLDER_RELEASE")

    if (DEFINED ${debug_variable})
        set(debug_root "${${debug_variable}}")
    endif()
    if (DEFINED ${release_variable})
        set(release_root "${${release_variable}}")
    endif()
    if (NOT debug_root AND release_root)
        set(debug_root "${release_root}")
    endif()
    if (NOT release_root AND debug_root)
        set(release_root "${debug_root}")
    endif()
    if (NOT debug_root OR NOT release_root)
        message(FATAL_ERROR
                "Conan package roots are unavailable for ${package_name}")
    endif()

    set(${output_variable}
            "$<IF:$<CONFIG:Debug>,${debug_root}/${relative_path},${release_root}/${relative_path}>"
            PARENT_SCOPE)
endfunction()

conan_package_license(IMGUI_LICENSE imgui licenses/LICENSE.txt)
conan_package_license(FREETYPE_FTL_LICENSE freetype licenses/FTL.TXT)
conan_package_license(FREETYPE_GPL2_LICENSE freetype licenses/GPLv2.TXT)
conan_package_license(BROTLI_LICENSE brotli licenses/LICENSE)
conan_package_license(BZIP2_LICENSE bzip2 licenses/LICENSE)
conan_package_license(LIBPNG_LICENSE libpng licenses/LICENSE)
conan_package_license(ZLIB_LICENSE zlib licenses/LICENSE)

# wolfGuard is a Linux kernel module. On Windows, UDP uses wolfSSL's native
# DTLS 1.3 implementation. Pin the release archive by digest and disable
# protocol and cipher families outside TrueTunnel's required profile.
include(FetchContent)
set(WOLFSSL_DTLS yes CACHE STRING "" FORCE)
set(WOLFSSL_TLS13 yes CACHE STRING "" FORCE)
set(WOLFSSL_DTLS13 yes CACHE STRING "" FORCE)
set(WOLFSSL_HRR_COOKIE yes CACHE STRING "" FORCE)
set(WOLFSSL_PSK yes CACHE STRING "" FORCE)
set(WOLFSSL_OLD_TLS no CACHE STRING "" FORCE)
set(WOLFSSL_TLSV12 no CACHE STRING "" FORCE)
set(WOLFSSL_RSA no CACHE STRING "" FORCE)
set(WOLFSSL_DH no CACHE STRING "" FORCE)
set(WOLFSSL_ASN yes CACHE STRING "" FORCE)
set(WOLFSSL_ECC yes CACHE STRING "" FORCE)
set(WOLFSSL_CURVE25519 no CACHE STRING "" FORCE)
set(WOLFSSL_CURVE448 no CACHE STRING "" FORCE)
set(WOLFSSL_ED25519 no CACHE STRING "" FORCE)
set(WOLFSSL_ED448 no CACHE STRING "" FORCE)
set(WOLFSSL_AES yes CACHE STRING "" FORCE)
set(WOLFSSL_AESGCM yes CACHE STRING "" FORCE)
set(WOLFSSL_AESCBC no CACHE STRING "" FORCE)
set(WOLFSSL_CHACHA no CACHE STRING "" FORCE)
set(WOLFSSL_POLY1305 no CACHE STRING "" FORCE)
set(WOLFSSL_SHA no CACHE STRING "" FORCE)
set(WOLFSSL_SHA224 no CACHE STRING "" FORCE)
set(WOLFSSL_SHA384 yes CACHE STRING "" FORCE)
set(WOLFSSL_SHA512 yes CACHE STRING "" FORCE)
set(WOLFSSL_SHA3 no CACHE STRING "" FORCE)
set(WOLFSSL_BASE64_ENCODE no CACHE STRING "" FORCE)
set(WOLFSSL_MLKEM no CACHE STRING "" FORCE)
set(WOLFSSL_PQC_HYBRIDS no CACHE BOOL "" FORCE)
set(WOLFSSL_EXTRA_PQC_HYBRIDS no CACHE STRING "" FORCE)
set(WOLFSSL_SNI no CACHE STRING "" FORCE)
set(WOLFSSL_SYS_CA_CERTS no CACHE STRING "" FORCE)
set(WOLFSSL_SESSION_TICKET no CACHE STRING "" FORCE)
set(WOLFSSL_FILESYSTEM no CACHE STRING "" FORCE)
set(WOLFSSL_EXAMPLES no CACHE STRING "" FORCE)
set(WOLFSSL_CRYPT_TESTS no CACHE STRING "" FORCE)
set(WOLFSSL_INSTALL no CACHE STRING "" FORCE)
set(WOLFSSL_HARDEN yes CACHE STRING "" FORCE)
set(WOLFSSL_ERROR_STRINGS yes CACHE STRING "" FORCE)

FetchContent_Declare(wolfssl
        URL https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.9.2-stable.tar.gz
        URL_HASH SHA256=2f4ef3d4fd387a9b3191d36a6316d69116c46ff69bb9583b6c82b36d7b8ca114
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(wolfssl)

# These supported features do not currently have first-class wolfSSL CMake
# options. PUBLIC keeps wolfSSL and every consumer on one ABI configuration.
target_compile_definitions(wolfssl PUBLIC
        WOLFSSL_DTLS_MTU
        HAVE_WRITE_DUP
)
if (MSVC)
    # wolfSSL's CMake file selects /Wall on Windows. Keep useful dependency
    # diagnostics without emitting thousands of SDK padding warnings.
    target_compile_options(wolfssl PRIVATE /W3)
endif()

set(VPN_SECURE_SOURCES
        src/secure/Transport.cpp
        src/secure/SecureSocket.cpp
        src/secure/SharedSecret.h
        src/secure/SchannelSocket.cpp
        src/secure/WolfSslDatagramSocket.cpp
)

set(VPN_CORE_SOURCES
        src/vpn.cpp
        src/utils.cpp
        src/VpnController.cpp
        src/core/VpnDaemon.cpp
        src/core/ConnectionRecovery.h
        src/Networking.cpp
        src/Networking.h
        src/IpPoolManager.cpp
        src/IpPoolManager.h
        src/VpnServer.cpp
        src/VpnServer.h
        src/VpnClient.cpp
        src/VpnClient.h
        src/security/FixedWindowRateLimiter.h
        ${VPN_SECURE_SOURCES}
)

set(VPN_GUI_SOURCES
        src/main.cpp
        src/ImGuiStyleManager.cpp
        src/ImGuiStyleManager.h
)

add_executable(vpn
        ${VPN_CORE_SOURCES}
        src/raii.hpp
        ${VPN_GUI_SOURCES}
)

if (BUILD_TESTING)
    # The exact production GUI compiled as an unelevated visual-test process.
    # It has no administrator manifest and never constructs the VPN daemon.
    add_executable(vpn_gui_visual_test
            ${VPN_CORE_SOURCES}
            src/raii.hpp
            ${VPN_GUI_SOURCES}
    )
    target_compile_definitions(vpn_gui_visual_test PRIVATE
            TRUETUNNEL_GUI_VISUAL_TEST
    )
endif()

add_executable(vpn_integration_test
        ${VPN_CORE_SOURCES}
        tests/VpnIntegrationTest.cpp
)
target_compile_definitions(vpn_integration_test PRIVATE
        TRUETUNNEL_INTEGRATION_TEST
)

if (BUILD_TESTING)
    add_executable(vpn_secure_transport_test
            ${VPN_SECURE_SOURCES}
            tests/SchannelSocketTest.cpp
    )
    target_compile_definitions(vpn_secure_transport_test PRIVATE
            TRUETUNNEL_SECURE_TRANSPORT_TEST
    )
    target_include_directories(vpn_secure_transport_test PRIVATE
            ${CMAKE_SOURCE_DIR}/src
    )
    add_test(NAME vpn_secure_transport_test COMMAND vpn_secure_transport_test)
    set_tests_properties(vpn_secure_transport_test PROPERTIES TIMEOUT 60)

    add_executable(vpn_redirect_stream_test
            tests/RedirectStreamTest.cpp
    )
    target_include_directories(vpn_redirect_stream_test PRIVATE
            ${CMAKE_SOURCE_DIR}/src
    )
    if (MSVC)
        target_compile_options(vpn_redirect_stream_test PRIVATE
                /W4 /WX /permissive- /sdl /GS)
    endif()
    add_test(NAME vpn_redirect_stream_test COMMAND vpn_redirect_stream_test)
    set_tests_properties(vpn_redirect_stream_test PROPERTIES TIMEOUT 15)

    add_test(NAME vpn_wintun_loader_test
            COMMAND vpn_integration_test --wintun-load-only)
    set_tests_properties(vpn_wintun_loader_test PROPERTIES TIMEOUT 15)

    add_test(NAME vpn_wintun_identity_test
            COMMAND vpn_integration_test --wintun-identity-test)
    set_tests_properties(vpn_wintun_identity_test PROPERTIES TIMEOUT 15)

    add_test(NAME vpn_source_binding_test
            COMMAND vpn_integration_test --source-binding-test)
    set_tests_properties(vpn_source_binding_test PROPERTIES TIMEOUT 45)

    add_test(NAME vpn_wintun_tamper_test
            COMMAND powershell.exe -NoProfile -ExecutionPolicy Bypass
            -File "${CMAKE_SOURCE_DIR}/tests/WintunPinTest.ps1"
            -Executable "$<TARGET_FILE:vpn_integration_test>"
            -WintunDll "$<TARGET_FILE_DIR:vpn_integration_test>/wintun.dll")
    set_tests_properties(vpn_wintun_tamper_test PROPERTIES TIMEOUT 30)

    add_test(NAME vpn_gui_visual_test COMMAND vpn_gui_visual_test)
    set_tests_properties(vpn_gui_visual_test PROPERTIES TIMEOUT 60)
endif()

if (MSVC)
    target_compile_options(vpn PRIVATE
            /W4           # High warning level
            /WX           # Treat warnings as errors
            /permissive-  # Strict ISO C++ conformance
    )
else()
    target_compile_options(vpn PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
            -Wshadow -Wnull-dereference -Wold-style-cast -Wnon-virtual-dtor
            -Woverloaded-virtual -Wformat=2 -Wimplicit-fallthrough
            -Wduplicated-cond -Wduplicated-branches -Wlogical-op
            -Wuseless-cast -Wdouble-promotion -Wno-unused-parameter
           # -Werror
    )
endif()

if (MSVC)
    target_compile_options(vpn_integration_test PRIVATE
            /W4
            /WX
            /permissive-
    )
else()
    target_compile_options(vpn_integration_test PRIVATE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
            -Wshadow -Wnull-dereference -Wold-style-cast -Wnon-virtual-dtor
            -Woverloaded-virtual -Wformat=2 -Wimplicit-fallthrough
            -Wduplicated-cond -Wduplicated-branches -Wlogical-op
            -Wuseless-cast -Wdouble-promotion -Wno-unused-parameter
    )
endif()

if (BUILD_TESTING)
    if (MSVC)
        target_compile_options(vpn_gui_visual_test PRIVATE
                /W4 /WX /permissive- /sdl /GS)
    else()
        target_compile_options(vpn_gui_visual_test PRIVATE
                -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
                -Wshadow -Wnull-dereference -Wold-style-cast -Wnon-virtual-dtor
                -Woverloaded-virtual -Wformat=2 -Wimplicit-fallthrough)
    endif()
endif()

if (BUILD_TESTING)
    if (MSVC)
        target_compile_options(vpn_secure_transport_test PRIVATE
                /W4
                /WX
                /permissive-
                /sdl
                /GS
        )
    else()
        target_compile_options(vpn_secure_transport_test PRIVATE
                -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
                -Wshadow -Wnull-dereference -Wold-style-cast -Wnon-virtual-dtor
                -Woverloaded-virtual -Wformat=2 -Wimplicit-fallthrough
        )
    endif()
endif()

if (MSVC)
    target_compile_options(vpn PRIVATE
            /guard:cf            # Control Flow Guard
            /sdl                 # Enable additional security checks
            /GS                  # Buffer security checks
            $<$<CONFIG:Release>:/Zo->
    )
    target_link_options(vpn PRIVATE
            /guard:cf
            /HIGHENTROPYVA       # High entropy ASLR
            /DYNAMICBASE         # Enable ASLR
            /NXCOMPAT            # Mark as compatible with DEP
            /CETCOMPAT      # Enable Intel CET shadow stack (Win10+ hardware)
            $<$<CONFIG:Release>:/RELEASE>
            $<$<CONFIG:Release>:/DEBUG:NONE>
    )
endif()

if (BUILD_TESTING AND MSVC)
    target_link_options(vpn_gui_visual_test PRIVATE
            /guard:cf
            /HIGHENTROPYVA
            /DYNAMICBASE
            /NXCOMPAT
            /CETCOMPAT
    )
endif()

set_property(TARGET vpn PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)





target_sources(vpn PRIVATE
        ${IMGUI_BACKENDS_DIR}/imgui_impl_win32.cpp
        ${IMGUI_BACKENDS_DIR}/imgui_impl_dx11.cpp
        ${IMGUI_MISC_DIR}/freetype/imgui_freetype.cpp
)

if (BUILD_TESTING)
    target_sources(vpn_gui_visual_test PRIVATE
            ${IMGUI_BACKENDS_DIR}/imgui_impl_win32.cpp
            ${IMGUI_BACKENDS_DIR}/imgui_impl_dx11.cpp
            ${IMGUI_MISC_DIR}/freetype/imgui_freetype.cpp
    )
endif()


# 👉 ADD THIS after add_executable
set_target_properties(vpn PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:WINDOWS"
        ENABLE_EXPORTS FALSE
        POSITION_INDEPENDENT_CODE ON
)

if (BUILD_TESTING)
    set_target_properties(vpn_gui_visual_test PROPERTIES
            LINK_FLAGS "/SUBSYSTEM:WINDOWS"
            ENABLE_EXPORTS FALSE
            POSITION_INDEPENDENT_CODE ON
    )
endif()


# Includes
target_include_directories(vpn PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/include
        ${IMGUI_BACKENDS_DIR}
        ${IMGUI_MISC_DIR}                 # ✅ needed for freetype headers
        ${IMGUI_MISC_DIR}/freetype       # ✅ contains imgui_freetype.h
)

if (BUILD_TESTING)
    target_include_directories(vpn_gui_visual_test PRIVATE
            ${CMAKE_SOURCE_DIR}/src
            ${CMAKE_SOURCE_DIR}/src/include
            ${IMGUI_BACKENDS_DIR}
            ${IMGUI_MISC_DIR}
            ${IMGUI_MISC_DIR}/freetype
    )
endif()

target_include_directories(vpn_integration_test PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/src/include
)



# Link Windows platform libraries and package-provided targets.
target_link_libraries(vpn PRIVATE
        wolfssl::wolfssl
        ws2_32
        secur32
        ncrypt
        ole32
        iphlpapi
        bcrypt
        crypt32
        advapi32
        imgui::imgui
        d3d11
        dxgi
        dxguid
        Freetype::Freetype
        dwmapi

)

if (BUILD_TESTING)
    target_link_libraries(vpn_gui_visual_test PRIVATE
            wolfssl::wolfssl
            ws2_32
            secur32
            ncrypt
            ole32
            iphlpapi
            bcrypt
            crypt32
            advapi32
            imgui::imgui
            d3d11
            dxgi
            dxguid
            Freetype::Freetype
            dwmapi
            windowscodecs
    )
endif()

target_link_libraries(vpn_integration_test PRIVATE
        wolfssl::wolfssl
        ws2_32
        secur32
        ncrypt
        ole32
        iphlpapi
        bcrypt
        crypt32
        advapi32
        setupapi
        shell32
        winmm
)

if (BUILD_TESTING)
    target_link_libraries(vpn_secure_transport_test PRIVATE
            wolfssl::wolfssl
            ws2_32
            secur32
            ncrypt
            bcrypt
            crypt32
    )
endif()

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

# Headless harness to exercise the VPN daemon abstraction without GUI dependencies
add_executable(vpn_daemon_harness
        tests/VpnDaemonHarness.cpp
        src/core/VpnDaemon.cpp
)

target_include_directories(vpn_daemon_harness PRIVATE
        ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(vpn_daemon_harness PRIVATE
        VPN_DAEMON_DISABLE_DEFAULT_FACTORY
)

if (MSVC)
    target_compile_options(vpn_daemon_harness PRIVATE
            /W4 /WX /permissive- /sdl /GS)
endif()

if (BUILD_TESTING)
    add_test(NAME vpn_daemon_harness COMMAND vpn_daemon_harness)
    set_tests_properties(vpn_daemon_harness PROPERTIES TIMEOUT 15)
endif()

# Embed a manifest so the EXE auto-elevates on Windows 
set(EXE_MANIFEST "${CMAKE_SOURCE_DIR}/deps/vpn.exe.manifest")
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
            -manifest "${EXE_MANIFEST}"
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

# Copy runtime and redistribution files to the build directory.
add_custom_command(TARGET vpn POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:vpn>"
        COMMAND ${CMAKE_COMMAND} -E make_directory
        "$<TARGET_FILE_DIR:vpn>/licenses"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/deps/wintun.dll"
        "$<TARGET_FILE_DIR:vpn>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/readme.md"
        "$<TARGET_FILE_DIR:vpn>/README.md"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/LICENSE"
        "$<TARGET_FILE_DIR:vpn>/licenses/TrueTunnel-LICENSE.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/NOTICE"
        "$<TARGET_FILE_DIR:vpn>/licenses/TrueTunnel-NOTICE.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/THIRD_PARTY.md"
        "$<TARGET_FILE_DIR:vpn>/licenses/THIRD_PARTY.md"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/licenses/Wintun-PREBUILT-LICENSE.txt"
        "$<TARGET_FILE_DIR:vpn>/licenses/Wintun-PREBUILT-LICENSE.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${wolfssl_SOURCE_DIR}/LICENSING"
        "$<TARGET_FILE_DIR:vpn>/licenses/wolfSSL-LICENSING.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${wolfssl_SOURCE_DIR}/COPYING"
        "$<TARGET_FILE_DIR:vpn>/licenses/wolfSSL-GPLv3.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${IMGUI_LICENSE}"
        "$<TARGET_FILE_DIR:vpn>/licenses/Dear-ImGui-MIT.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${FREETYPE_FTL_LICENSE}"
        "$<TARGET_FILE_DIR:vpn>/licenses/FreeType-FTL.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${FREETYPE_GPL2_LICENSE}"
        "$<TARGET_FILE_DIR:vpn>/licenses/FreeType-GPLv2.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${BROTLI_LICENSE}"
        "$<TARGET_FILE_DIR:vpn>/licenses/Brotli-LICENSE.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${BZIP2_LICENSE}"
        "$<TARGET_FILE_DIR:vpn>/licenses/bzip2-LICENSE.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${LIBPNG_LICENSE}"
        "$<TARGET_FILE_DIR:vpn>/licenses/libpng-LICENSE.txt"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${ZLIB_LICENSE}"
        "$<TARGET_FILE_DIR:vpn>/licenses/zlib-LICENSE.txt"
        VERBATIM
)

add_custom_command(TARGET vpn_integration_test POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory "$<TARGET_FILE_DIR:vpn_integration_test>"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_SOURCE_DIR}/deps/wintun.dll"
        "$<TARGET_FILE_DIR:vpn_integration_test>"
)

if (WIN32)
    target_sources(vpn PRIVATE ${CMAKE_SOURCE_DIR}/src/version.rc)
    if (BUILD_TESTING)
        target_sources(vpn_gui_visual_test PRIVATE ${CMAKE_SOURCE_DIR}/src/version.rc)
    endif()
endif()

# Remove .lib and .exp files from the output directory
add_custom_command(TARGET vpn POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E remove -f
        "$<TARGET_FILE_DIR:vpn>/vpn.lib"
        "$<TARGET_FILE_DIR:vpn>/vpn.exp"
        "$<TARGET_FILE_DIR:vpn>/vpn.pdb"
        COMMENT "Deleting MSVC-generated .lib/.exp files from output"
)
# Set build type name safely (since multi-config generators like Visual Studio won't define it at configure time)
string(TOLOWER "$<CONFIG>" build_type)

# Use generator expression for config-specific output folder
set(zip_output_dir "$<TARGET_FILE_DIR:vpn>")
set(zip_filename "$<TARGET_FILE_DIR:vpn>/TrueTunnel-VPN-$<CONFIG>.zip")

# Package runtime files, documentation, and the exact license texts used by the
# selected build configuration. Corresponding Source remains a distributor
# obligation for GPLv3 builds; the notices do not replace it.
add_custom_command(TARGET vpn POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Zipping TrueTunnel: $<CONFIG>"
        COMMAND ${CMAKE_COMMAND} -E tar "cfv"
        "${zip_filename}" --format=zip
        -- "$<TARGET_FILE:vpn>"
        "${zip_output_dir}/wintun.dll"
        "${zip_output_dir}/README.md"
        "${zip_output_dir}/licenses"
        COMMENT "Packing release zip: TrueTunnel-$<CONFIG>.zip"
)
