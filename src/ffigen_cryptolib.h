#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>

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

/**
* Ham ma hoa file
	Chuc nang:			ma hoa file de gui cho danh sach user

	Tham so:
	inputFileName		ten file ro dau vao
	outputFileName		ten file ma dau ra
	listUserID			danh sach ID cua USER
	listUserPubKey		danh sach pubkey cua USER (pubkey doc tu file dinh dang .pem, pubkey cua tung User phan biet bang dau ';')
	numUser				so luong User

	Tra ve:
	0				neu thanh cong
	khac			neu co loi
*/
	FFI_PLUGIN_EXPORT int Zalo_EncryptFile(const wchar_t *inputFileName, const wchar_t *outputFileName,
	unsigned int *listUserID, const char *listUserPubKey, unsigned int numUser);

/**
* Ham giai ma file
	Chuc nang:			giai ma file nhan duoc tu server

	Tham so:
	inputFileName		ten file ma dau vao
	outputFileName		ten file giai ma dau ra
	userID				ID cua USER
	userPrivKey			khoa bi mat cua user (doc tu file dinh dang .pem)
	userPrivKeyLen		do dai du lieu khoa bi mat user
	pass				mat khau khoa bi mat user (day cung chinh la mat khau dang nhap cua user)

	Tra ve:
	0				neu thanh cong
	khac			neu co loi
*/

	FFI_PLUGIN_EXPORT int Zalo_DecryptFile(const wchar_t *inputFileName, const wchar_t *outputFileName, unsigned int userID,
	const char *userPrivKey, unsigned int userPrivKeyLen, const char *pass);

/**
* Ham doi mat khau private key
	Chuc nang:			doi mat khau khoa bi mat

	Tham so:
	inPrivKey			khoa bi mat dau vao (doc tu file dinh dang .pem)
	inPrivKeyLen		do dai du lieu khoa bi mat
	oldPass				mat khau khoa cu
	outPrivKey			khoa bi mat dau ra
	outPrivKeyLen		do dai du lieu khoa bi mat dau ra
	outPrivKeyMaxLen	do dai toi da du lieu khoa bi mat dau ra
	newPass				mat khau khoa moi

	Tra ve:
	0				neu thanh cong
	khac			neu co loi
*/
	FFI_PLUGIN_EXPORT int Zalo_ChangePrivKeyPass(const char *inPrivKey, unsigned int inPrivKeyLen, const char *oldPass,
	char *outPrivKey, unsigned int *outPrivKeyLen, unsigned int outPrivKeyMaxLen, const char *newPass);

/**
* Ham ma hoa tin nhan
	Chuc nang:			ma hoa tin nhan de gui cho danh sach user

	Tham so:
	inMes				tin nhan ro dau vao
	inMesLen			do dai tin nhan ro dau vao
	outMes				ban ma tin nhan dau ra
	outMesLen			do dai ban ma tin nhan dau ra
	outMesMaxLen		do dai toi da cua ban ma tin nhan dau ra
	listUserID			danh sach ID cua USER
	listUserPubKey		danh sach pubkey cua USER (pubkey doc tu file dinh dang .pem, pubkey cua tung User phan biet bang dau ';')
	numUser				so luong User

	Tra ve:
	0				neu thanh cong
	khac			neu co loi
*/
	FFI_PLUGIN_EXPORT int Zalo_EncryptMessage(const unsigned char *inMes, unsigned int inMesLen,
	unsigned char *outMes, unsigned int *outMesLen, unsigned int outMesMaxLen,
	unsigned int *listUserID, const char *listUserPubKey, unsigned int numUser);

/**
* Ham giai ma tin nhan
	Chuc nang:			giai ma tin nhan nhan duoc tu server

	Tham so:
	inMes				ban ma tin nhan dau vao
	inMesLen			do dai ban ma tin nhan dau vao
	outMes				ban giai ma tin nhan dau ra
	outMesLen			do dai ban giai ma tin nhan dau ra
	outMesMaxLen		do dai toi da cua ban giai ma tin nhan dau ra
	userID				ID cua USER
	userPrivKey			khoa bi mat cua user (doc tu file dinh dang .pem)
	userPrivKeyLen		do dai du lieu khoa bi mat user
	pass				mat khau khoa bi mat user (day cung chinh la mat khau dang nhap cua user)

	Tra ve:
	0				neu thanh cong
	khac			neu co loi
*/

	FFI_PLUGIN_EXPORT int Zalo_DecryptMessage(const unsigned char *inMes, unsigned int inMesLen,
	unsigned char *outMes, unsigned int *outMesLen, unsigned int outMesMaxLen,
	unsigned int userID, const char* userPrivKey, unsigned int userPrivKeyLen, const char* pass);


	FFI_PLUGIN_EXPORT const char *Zalo_Error(int errNum);


#ifdef __cplusplus
}
#endif

#endif
