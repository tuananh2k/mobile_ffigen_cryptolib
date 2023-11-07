#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

#if _WIN32
#define FFI_PLUGIN_EXPORT __declspec(dllexport)
#else
#define FFI_PLUGIN_EXPORT
#endif

#pragma once
#ifndef CRYPTOLIB_H
#define CRYPTOLIB_H

#ifdef __cplusplus
extern "C" {
#endif
	#include <wchar.h>

#ifdef _WINDLL
#define ZALO_CRYPTOLIB_API __declspec(dllexport)
#else
#define ZALO_CRYPTOLIB_API __declspec(dllimport)
#endif

#define MAX_PUBKEY_LEN			4096
#define MAX_RSA_MODULUS_BYTE	512
#define MAX_BUFF_LEN			4096

#define AES256_KEY_LENGTH		32

// A very short-lived native function.
//
// For very short-lived functions, it is fine to call them on the main isolate.
// They will block the Dart execution while running the native function, so
// only do this for native functions which are guaranteed to be short-lived.
FFI_PLUGIN_EXPORT intptr_t sum(intptr_t a, intptr_t b);

// A longer lived native function, which occupies the thread calling it.
//
// Do not call these kind of native functions in the main isolate. They will
// block Dart execution. This will cause dropped frames in Flutter applications.
// Instead, call these native functions on a separate isolate.
FFI_PLUGIN_EXPORT intptr_t sum_long_running(intptr_t a, intptr_t b);

FFI_PLUGIN_EXPORT const char* return_string(const char* str);

FFI_PLUGIN_EXPORT const char* print_file_info(char *filename);


#ifdef __cplusplus
}
#endif

#endif
