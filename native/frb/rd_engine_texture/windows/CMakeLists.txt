cmake_minimum_required(VERSION 3.14)

set(PROJECT_NAME "rd_engine_texture")
project(${PROJECT_NAME} LANGUAGES CXX)

cmake_policy(VERSION 3.14...3.25)
set(PLUGIN_NAME "rd_engine_texture_plugin")

# The plugin is intentionally limited to the generated C API registration
# source and the stock Flutter Windows wrapper. The engine header is consumed
# from this repository; it is never copied into the plugin or reimplemented.
list(APPEND PLUGIN_SOURCES
  "rd_engine_texture_plugin.cpp"
  "rd_engine_texture_plugin.h"
  "include/rd_engine_texture/rd_engine_texture_plugin_c_api.h"
)

add_library(${PLUGIN_NAME} SHARED ${PLUGIN_SOURCES})
apply_standard_settings(${PLUGIN_NAME})
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
target_compile_features(${PLUGIN_NAME} PRIVATE cxx_std_17)

target_include_directories(${PLUGIN_NAME}
  PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

# Resolve the frozen engine ABI header from the real plugin source directory.
# The generated plugin build may enter through .plugin_symlinks, so resolve the
# path before validating it. An integration build can provide the same
# canonical directory explicitly, but no alternate header is accepted.
get_filename_component(RD_ENGINE_TEXTURE_SOURCE_DIR
  "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
get_filename_component(RD_ENGINE_TEXTURE_CANONICAL_HEADER_DIR
  "${RD_ENGINE_TEXTURE_SOURCE_DIR}/../../include" REALPATH)
if(DEFINED ENV{RD_ENGINE_WINDOWS_TEXTURE_INCLUDE_DIR} AND
   NOT "$ENV{RD_ENGINE_WINDOWS_TEXTURE_INCLUDE_DIR}" STREQUAL "")
  get_filename_component(RD_ENGINE_TEXTURE_HEADER_DIR
    "$ENV{RD_ENGINE_WINDOWS_TEXTURE_INCLUDE_DIR}" REALPATH)
  if(NOT RD_ENGINE_TEXTURE_HEADER_DIR STREQUAL RD_ENGINE_TEXTURE_CANONICAL_HEADER_DIR)
    message(FATAL_ERROR "The Windows texture ABI must use the canonical engine header directory")
  endif()
else()
  set(RD_ENGINE_TEXTURE_HEADER_DIR
      "${RD_ENGINE_TEXTURE_CANONICAL_HEADER_DIR}")
endif()
set(RD_ENGINE_TEXTURE_HEADER
    "${RD_ENGINE_TEXTURE_HEADER_DIR}/rd_engine_windows_texture.h")
if(NOT EXISTS "${RD_ENGINE_TEXTURE_HEADER}")
  message(FATAL_ERROR
    "rd_engine_windows_texture.h is required at ${RD_ENGINE_TEXTURE_HEADER}; "
    "set RD_ENGINE_WINDOWS_TEXTURE_INCLUDE_DIR to the canonical native/frb/include directory")
endif()

target_include_directories(${PLUGIN_NAME} PRIVATE
  "${RD_ENGINE_TEXTURE_HEADER_DIR}")
target_sources(${PLUGIN_NAME} PRIVATE "${RD_ENGINE_TEXTURE_HEADER}")
target_link_libraries(${PLUGIN_NAME} PRIVATE
  flutter
  flutter_wrapper_plugin
  user32
  d3d11
  dxgi)

set(rd_engine_texture_bundled_libraries "" PARENT_SCOPE)
