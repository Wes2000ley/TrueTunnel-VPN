cmake_minimum_required(VERSION 3.20)
project(vpn)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Always build static binaries
set(BUILD_SHARED_LIBS OFF)
set(CONAN_CMAKE_FLAGS "--build=missing")
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)




# On MSVC: use the static CRT
if (MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif ()


# Required for finding Conan packages
find_package(OpenSSL REQUIRED)
find_package(imgui REQUIRED)
find_package(freetype)
set(IMGUI_BACKENDS_DIR "${CMAKE_SOURCE_DIR}/deps/imgui/backends")
set(IMGUI_MISC_DIR "${CMAKE_SOURCE_DIR}/deps/imgui/misc")



add_executable(vpn
      #  src/include/applink.c
        src/vpn.cpp
        src/utils.cpp
        src/VpnController.cpp
        src/raii.hpp
        src/main.cpp
        src/ImGuiStyleManager.cpp
        src/ImGuiStyleManager.h
)

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
            -Werror
    )
endif()

if (MSVC)
    target_compile_options(vpn PRIVATE
            /guard:cf            # Control Flow Guard
            /sdl                 # Enable additional security checks
            /GS                  # Buffer security checks
    )
    target_link_options(vpn PRIVATE
            /guard:cf
            /HIGHENTROPYVA       # High entropy ASLR
            /DYNAMICBASE         # Enable ASLR
            /NXCOMPAT            # Mark as compatible with DEP
    )
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(vpn PROPERTIES
            INTERPROCEDURAL_OPTIMIZATION TRUE # already enabled globally, but safe to reinforce
    )
    if (MSVC)
        target_compile_options(vpn PRIVATE /Zo-) # Disable debug info
    else()
        target_compile_options(vpn PRIVATE -g0)
    endif()
endif()





target_sources(vpn PRIVATE
        ${IMGUI_BACKENDS_DIR}/imgui_impl_win32.cpp
        ${IMGUI_BACKENDS_DIR}/imgui_impl_dx11.cpp
        ${IMGUI_MISC_DIR}/freetype/imgui_freetype.cpp
)


# 👉 ADD THIS after add_executable
set_target_properties(vpn PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:WINDOWS"
        ENABLE_EXPORTS FALSE
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
        ${IMGUI_BACKENDS_DIR}
        ${IMGUI_MISC_DIR}                 # ✅ needed for freetype headers
        ${IMGUI_MISC_DIR}/freetype       # ✅ contains imgui_freetype.h
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
        imgui::imgui
        d3d11
        dxgi
        dxguid
        Freetype::Freetype

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

# Only include files that exist; skip manifest if embedded
add_custom_command(TARGET vpn POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E echo "Zipping TrueTunnel: $<CONFIG>"
        COMMAND ${CMAKE_COMMAND} -E tar "cfv"
        "${zip_filename}" --format=zip
        -- "$<TARGET_FILE:vpn>"
        "${zip_output_dir}/wintun.dll"
        "${zip_output_dir}/fips.dll"
        "${zip_output_dir}/openssl.exe"
        "${zip_output_dir}/run_fipsinstall.bat"
        "${zip_output_dir}/openssl.cnf"
        COMMENT "Packing release zip: TrueTunnel-$<CONFIG>.zip"
)
