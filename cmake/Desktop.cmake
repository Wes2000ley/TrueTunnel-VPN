# The frontend is compiled into the executable; no local HTTP listener, runtime
# npm install, external script, or writable asset directory is used in release.
find_program(TRUETUNNEL_NODE NAMES node REQUIRED)
execute_process(COMMAND "${TRUETUNNEL_NODE}" -p "((v) => v[0] > 22 || (v[0] === 22 && v[1] >= 12))(process.versions.node.split('.').map(Number))"
        OUTPUT_VARIABLE NODE_SUPPORTED OUTPUT_STRIP_TRAILING_WHITESPACE)
if (NOT NODE_SUPPORTED STREQUAL "true")
    message(FATAL_ERROR "TrueTunnel desktop requires Node.js 22.12+; select it with -DTRUETUNNEL_NODE=<path to node.exe>")
endif()
find_program(TRUETUNNEL_NPM NAMES npm.cmd npm REQUIRED)

FetchContent_Declare(webview2
        URL https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/1.0.4191.47/microsoft.web.webview2.1.0.4191.47.nupkg
        URL_HASH SHA256=f492bbf547d0da329553b6727435b677579b1e9f91cc9e4a1ad029366d5f23d0
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(webview2)
set(JSON_HEADER "${CMAKE_BINARY_DIR}/desktop-dependencies/json.hpp")
file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}/desktop-dependencies")
if (NOT EXISTS "${JSON_HEADER}")
    file(DOWNLOAD https://github.com/nlohmann/json/releases/download/v3.12.0/json.hpp "${JSON_HEADER}"
            EXPECTED_HASH SHA256=aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63 TLS_VERIFY ON)
endif()
file(SHA256 "${JSON_HEADER}" JSON_HASH)
if (NOT JSON_HASH STREQUAL "aaf127c04cb31c406e5b04a63f1ae89369fccde6d8fa7cdda1ed4f32dfc5de63")
    message(FATAL_ERROR "The pinned nlohmann JSON header has changed")
endif()

# npm.cmd may select its own adjacent node.exe. Invoke the CLI with the chosen
# Node when installed by nvm, while retaining standard npm discovery elsewhere.
get_filename_component(NPM_DIRECTORY "${TRUETUNNEL_NPM}" DIRECTORY)
if (EXISTS "${NPM_DIRECTORY}/node_modules/npm/bin/npm-cli.js")
    set(NPM_COMMAND "${TRUETUNNEL_NODE}" "${NPM_DIRECTORY}/node_modules/npm/bin/npm-cli.js")
else()
    set(NPM_COMMAND "${TRUETUNNEL_NPM}")
endif()
get_filename_component(NODE_DIRECTORY "${TRUETUNNEL_NODE}" DIRECTORY)
set(FRONTEND_DIR "${CMAKE_SOURCE_DIR}/frontend")
set(ASSET_DIR "${CMAKE_BINARY_DIR}/desktop-assets")
file(GLOB_RECURSE FRONTEND_SOURCES CONFIGURE_DEPENDS "${FRONTEND_DIR}/src/*" "${FRONTEND_DIR}/scripts/*" "${FRONTEND_DIR}/tests/*")
add_custom_command(OUTPUT "${CMAKE_BINARY_DIR}/frontend-dependencies.stamp"
        COMMAND ${NPM_COMMAND} ci --ignore-scripts
        COMMAND ${CMAKE_COMMAND} -E touch "${CMAKE_BINARY_DIR}/frontend-dependencies.stamp"
        DEPENDS "${FRONTEND_DIR}/package.json" "${FRONTEND_DIR}/package-lock.json"
        WORKING_DIRECTORY "${FRONTEND_DIR}" VERBATIM)
add_custom_command(OUTPUT "${ASSET_DIR}/DesktopAssets.rc" "${ASSET_DIR}/DesktopAssets.h"
        COMMAND "${TRUETUNNEL_NODE}" "${FRONTEND_DIR}/node_modules/typescript/bin/tsc" --noEmit
        COMMAND "${TRUETUNNEL_NODE}" "${FRONTEND_DIR}/node_modules/vite/bin/vite.js" build
        COMMAND "${TRUETUNNEL_NODE}" "${FRONTEND_DIR}/scripts/embed.mjs" "${ASSET_DIR}"
        DEPENDS ${FRONTEND_SOURCES} "${CMAKE_BINARY_DIR}/frontend-dependencies.stamp"
        "${FRONTEND_DIR}/index.html" "${FRONTEND_DIR}/vite.config.ts" "${FRONTEND_DIR}/playwright.config.ts" "${FRONTEND_DIR}/tsconfig.json"
        WORKING_DIRECTORY "${FRONTEND_DIR}" VERBATIM)
add_custom_target(truetunnel_frontend DEPENDS "${ASSET_DIR}/DesktopAssets.rc" "${ASSET_DIR}/DesktopAssets.h")
target_sources(vpn PRIVATE src/desktop/DesktopHost.cpp src/desktop/Broker.cpp src/version.rc "${ASSET_DIR}/DesktopAssets.rc")
add_dependencies(vpn truetunnel_frontend)
target_include_directories(vpn PRIVATE "${ASSET_DIR}" "${CMAKE_BINARY_DIR}/desktop-dependencies")
target_include_directories(vpn SYSTEM PRIVATE "${webview2_SOURCE_DIR}/build/native/include")
target_link_libraries(vpn PRIVATE "${webview2_SOURCE_DIR}/build/native/x64/WebView2LoaderStatic.lib" shlwapi version dwmapi userenv)
target_compile_definitions(vpn PRIVATE UNICODE _UNICODE)
target_link_options(vpn PRIVATE /SUBSYSTEM:WINDOWS /MANIFEST:EMBED "/MANIFESTINPUT:${CMAKE_SOURCE_DIR}/src/desktop/desktop.manifest")

if (BUILD_TESTING)
    add_executable(vpn_desktop_bridge_test tests/DesktopBridgeTest.cpp)
    target_include_directories(vpn_desktop_bridge_test PRIVATE "${CMAKE_SOURCE_DIR}/src")
    target_link_libraries(vpn_desktop_bridge_test PRIVATE bcrypt advapi32)
    target_compile_options(vpn_desktop_bridge_test PRIVATE /W4 /WX /permissive- /sdl /GS)
    add_test(NAME vpn_desktop_bridge_test COMMAND vpn_desktop_bridge_test)
    set_tests_properties(vpn_desktop_bridge_test PROPERTIES TIMEOUT 20)
    add_test(NAME vpn_gui_visual_test COMMAND vpn_integration_test --gui-smoke-only)
    set_tests_properties(vpn_gui_visual_test PROPERTIES TIMEOUT 40)
endif()
