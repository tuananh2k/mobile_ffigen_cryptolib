# The Flutter tooling requires that developers have CMake 3.10 or later
# installed. You should not increase this version, as doing so will cause
# the plugin to fail to compile for some customers of the plugin.
cmake_minimum_required(VERSION 3.10)

project(ffigen_cryptolib_library VERSION 0.0.1 LANGUAGES C)

add_library(ffigen_cryptolib SHARED
  "ffigen_cryptolib.c"
)

set_target_properties(ffigen_cryptolib PROPERTIES
  PUBLIC_HEADER ffigen_cryptolib.h
  OUTPUT_NAME "ffigen_cryptolib"
)

target_compile_definitions(ffigen_cryptolib PUBLIC DART_SHARED_LIB)
