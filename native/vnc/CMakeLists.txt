cmake_minimum_required(VERSION 3.16)
project(rd_engine_vnc LANGUAGES C)

# Upstream declares CMake 3.4; CMake 4 removed compatibility below 3.5.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
# Baseline capabilities are deliberate, not auto-detected advertised features.
# Zlib is mandatory: a build missing Zlib/ZRLE is not this product's VNC client.
find_package(ZLIB REQUIRED)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(LIBVNCSERVER_INSTALL OFF CACHE BOOL "" FORCE)
set(WITH_ZLIB ON CACHE BOOL "" FORCE)
foreach(feature LZO JPEG PNG SDL GTK LIBSSHTUNNEL THREADS GNUTLS OPENSSL
                SYSTEMD GCRYPT FFMPEG TIGHTVNC_FILETRANSFER WEBSOCKETS SASL
                XCB EXAMPLES TESTS QT)
    set(WITH_${feature} OFF CACHE BOOL "" FORCE)
endforeach()
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_subdirectory(upstream EXCLUDE_FROM_ALL)
target_sources(vncclient PRIVATE rd_vnc.c)
# cmake-rs replaces MSVC's default C flags, including its WIN32 definition.
# Upstream needs it before zlib headers and their platform-dependent typedefs.
if(WIN32)
    target_compile_definitions(vncclient PRIVATE WIN32)
endif()
target_include_directories(vncclient PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/upstream/include"
    "${CMAKE_CURRENT_BINARY_DIR}/upstream/include")
set_target_properties(vncclient PROPERTIES
    C_STANDARD 99
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
foreach(configuration DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    set_target_properties(vncclient PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY_${configuration} "${CMAKE_BINARY_DIR}/lib")
endforeach()
# Visual Studio resolves explicit build targets from this directory. Keep the
# upstream project in its own subdirectory and expose only its client here.
add_custom_target(rd_engine_vnc_client DEPENDS vncclient)
file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/rd_vnc_zlib_$<CONFIG>.txt"
     CONTENT "$<TARGET_LINKER_FILE:ZLIB::ZLIB>")
