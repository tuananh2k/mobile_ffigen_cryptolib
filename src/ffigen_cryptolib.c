#include "ffigen_cryptolib.h"
#include "error.h"
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

FFI_PLUGIN_EXPORT intptr_t sum(intptr_t a, intptr_t b) { return a + b; }

FFI_PLUGIN_EXPORT intptr_t sum_long_running(intptr_t a, intptr_t b) {
#if _WIN32
  Sleep(5000);
#else
  usleep(5000 * 1000);
#endif
  return a + b;
}

FFI_PLUGIN_EXPORT const char* return_string(const char* str) {
                      return str;
                  }

/**
* Doc du lieu tu file
* Doc 4 byte dau lay do dai buf
* Doc buf voi do dai da xac dinh
*/
static char *fread_v(FILE *file, unsigned int *lenbuf)
{
	char *buf = NULL;
	if (fread(lenbuf, 1, sizeof(int), file) != sizeof(int))
		return NULL;
	buf = (char *)malloc(*lenbuf + 1);
	memset(buf, 0, *lenbuf + 1);
	if (buf == NULL)
		return NULL;
	if (fread(buf, 1, *lenbuf, file) != *lenbuf)
		return NULL;
	return buf;
}

/**
* Ghi du lieu tu buff vao file
* Ghi 4 byte do dai buff
* Ghi du lieu buff
*/
static int fwrite_v(FILE *file, char *buf, unsigned int lenbuf)
{
	if (fwrite(&lenbuf, 1, sizeof(int), file) != sizeof(int))
		return -1;
	if (fwrite(buf, 1, lenbuf, file) != lenbuf)
		return -1;
	return 0;
}

static char *get_filename_ext(const wchar_t *filename) {
	char *dot = strrchr((char*)filename, '.');
	if (!dot || dot == (char*)filename) return "";
	return dot + 1;
}

static RSA *readRSApubkey(const char *key, unsigned int keyLen)
{
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, keyLen);
	if (keybio == NULL)
	{
		wprintf(L"Failed to create key BIO");
		return NULL;
	}

	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	BIO_free(keybio);

	return rsa;
}

static RSA *readRSAprivatekey(const char *key, unsigned int keyLen, const char *pass)
{
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, keyLen);
	if (keybio == NULL)
	{
		wprintf(L"Failed to create key BIO");
		return NULL;
	}

	rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, (char*)pass);

	BIO_free(keybio);
	return rsa;
}

static int writeRSAprivatekey(RSA *rsa, char *key, unsigned int *keyLen, unsigned int keyMaxLen, const char *pass)
{
	BIO *keybio;
	unsigned int len;

	memset(key, 0, keyMaxLen);
	keybio = BIO_new(BIO_s_mem());
	if (keybio == NULL)
	{
		wprintf(L"Co loi khi tao BIO\n");
		return ERR_CHANGE_PRIVKEY_PASS;
	}
	if (!PEM_write_bio_RSAPrivateKey(keybio, rsa, EVP_aes_256_cbc(), NULL, 0, NULL, (char *)pass))
	{
		wprintf(L"Co loi khi ghi privatekey vao BIO\n");
		BIO_free(keybio);
		return ERR_CHANGE_PRIVKEY_PASS;
	}
	len = BIO_pending(keybio);
	if (len + 1 > keyMaxLen)
	{
		BIO_free(keybio);
		return ERR_BAD_PRIVKEY_LENGTH;
	}
	if (BIO_read(keybio, key, len) <= 0)
	{
		wprintf(L"Co loi khi doc du lieu private key tu BIO\n");
		BIO_free(keybio);
		return ERR_CHANGE_PRIVKEY_PASS;
	}

	*keyLen = len;
	BIO_free(keybio);

	return 0;
}

FFI_PLUGIN_EXPORT int Zalo_EncryptFile(const wchar_t *inputFileName, const wchar_t *outputFileName, unsigned int *listUserID,
	const char *listUserPubKey, unsigned int numUser)
{
	FILE *inFile = NULL, *outFile = NULL;
	int ret;
	unsigned int i, j, k, countUser, wrapKeyLen, inLen, outLen,len, listUserPubKeyLen;
	unsigned int inFileSize, userID;
	SHA256_CTX sha256_ctx;
	EVP_CIPHER_CTX *aes_ctx = NULL;
	unsigned char sha256sum[SHA256_DIGEST_LENGTH];
	RSA *rsa = NULL;

	unsigned char ivSessionKey[AES_BLOCK_SIZE+ AES256_KEY_LENGTH]; //bien dung de luu IV va khoa phien
	unsigned char *userPubKey = NULL;
	unsigned char *wrapKey = NULL;
	unsigned char *inBuf = NULL, *outBuf = NULL; //[BUFF_READ_LEN];
	char *inputFileExt = NULL;

	if (inputFileName == NULL)
		return ERR_BAD_INPUT_FILENAME;
	if (outputFileName == NULL)
		return ERR_BAD_OUTPUT_FILENAME;
	if (listUserPubKey == NULL)
		return ERR_BAD_LIST_USERPUBKEY;
	if (listUserID == NULL)
		return ERR_BAD_LIST_USERID;

	//doc file dau vao va file dau ra
	//ret = fopen_s(&inFile, inputFileName, "rb");
	ret = _wfopen_s(&inFile, inputFileName, L"rb");
	if (ret)
	{
		wprintf(L"Co loi khi mo file dau vao: %s\n", inputFileName);
		return ERR_OPEN_INPUT_FILE;
	}
	//ret = fopen_s(&outFile, outputFileName, "wb");
	ret = _wfopen_s(&outFile, outputFileName, L"wb");
	if (ret)
	{
		wprintf(L"Co loi khi tao file dau ra: %s\n", outputFileName);
		ret = ERR_OPEN_OUTPUT_FILE;
		goto out;
	}

	//ghi tam so nguoi dung vao file truoc (sau se ghi lai so nguoi dung thuc te khi doc CTS cua nguoi dung)
	if (fwrite(&numUser, 1, sizeof(numUser), outFile) != sizeof(numUser))
	{
		wprintf(L"Khong ghi duoc so luong user\n");
		ret = ERR_WRITE_NUM_USER;
		goto out;
	}

	//ghi dinh dang file dau vao
	inputFileExt = get_filename_ext(inputFileName);
	if (fwrite_v(outFile, inputFileExt, strlen(inputFileExt)) != 0)
	{
		wprintf(L"Khong ghi duoc dinh dang file dau vao\n");
		ret = ERR_WRITE_INPUT_FILE_EXT;
		goto out;
	}



	//khoi tao bo nho cho du lieu
	userPubKey = (unsigned char *)malloc(MAX_PUBKEY_LEN);
	wrapKey = (unsigned char *)malloc(MAX_RSA_MODULUS_BYTE);
	inBuf = (unsigned char *)malloc(MAX_BUFF_LEN);
	outBuf = (unsigned char *)malloc(MAX_BUFF_LEN);
	if (userPubKey == NULL || wrapKey == NULL ||
		inBuf == NULL || outBuf == NULL)
	{
		wprintf(L"Khong khoi tao duoc bo nho cho du lieu!");
		ret = ERR_ALLOC_FAILED;
		goto out;
	}


	//sinh ngau nhien IV va khoa
	ret = RAND_bytes(ivSessionKey, AES_BLOCK_SIZE + AES256_KEY_LENGTH);
	if (ret  != 1)
	{
		wprintf(L" Loi khi sinh IV va khoa phien \n");
		ret = ERR_GENERATE_IV_KEY;
		goto out;
	}


	//doc chung thu so cua nguoi dung
	listUserPubKeyLen = strlen(listUserPubKey);
	j = 0;
	countUser = 0;
	for (i = 0, k = 0; i <= listUserPubKeyLen && k < numUser; i++)
	{
		if (listUserPubKey[i] != ';' && i < listUserPubKeyLen && j < MAX_PUBKEY_LEN)
		{
			if (j == 0)
				memset(userPubKey, 0, MAX_PUBKEY_LEN);
			userPubKey[j++] = listUserPubKey[i];
		}
		else
		{
			rsa = NULL;
			rsa = readRSApubkey(userPubKey, j);
			if (rsa == NULL)
			{
				wprintf(L"Khong doc duoc khoa cong khai cua nguoi dung\n");
				ret = ERR_READ_USER_PUBKEY;
				continue; //tiep tuc doc cert tiep theo
			}


			//ghi ID cua nguoi dung vao file
			userID = listUserID[k];
			if (fwrite(&userID, 1, sizeof(userID), outFile) != sizeof(userID))
			{
				wprintf(L"Khong ghi duoc ID nguoi dung\n");
				ret = ERR_WRITE_USER_ID;
				continue;
			}

			j = 0;
			k++;

			//ma hoa IV va khoa phien
			memset(wrapKey, 0, MAX_RSA_MODULUS_BYTE);
			ret = RSA_public_encrypt(sizeof(ivSessionKey), ivSessionKey, wrapKey, rsa, RSA_PKCS1_OAEP_PADDING);
			if (ret == -1)
			{
				wprintf(L"Khong ma hoa duoc IV va khoa phien\n ");
				ret = ERR_ENCRYPT_IV_KEY;
				continue;
			}
			wrapKeyLen = ret;
			//ghi WrapKey vao file
			if (fwrite_v(outFile, wrapKey, wrapKeyLen) != 0)
			{
				wprintf(L"Khong ghi duoc wrapkey\n");
				ret = ERR_WRITE_WRAPKEY;
				continue;
			}
			else
			{
				countUser++;
			}
		}
	}

	if (countUser == 0)
	{
		wprintf(L"Khong doc duoc chung thu so nao cua user\n");
		ret = ERR_READ_ALL_USER_PUBKEY;
		goto out;
	}

	//ghi lai so luong user thuc te len dau file
	rewind(outFile);
	if (fwrite(&countUser, 1, sizeof(int), outFile) != sizeof(int))
	{
		wprintf(L"Khong ghi duoc so luong user\n");
		ret = ERR_WRITE_NUM_USER;
		goto out;
	}
	fseek(outFile, 0, SEEK_END);

	//ghi dung luong file ban dau len file
	fseek(inFile, 0, SEEK_END);
	inFileSize = ftell(inFile);
	rewind(inFile);
	if (fwrite(&inFileSize, 1, sizeof(int), outFile) != sizeof(int))
	{
		wprintf(L"Khong ghi duoc dung luong file ban dau\n");
		ret = ERR_WRITE_ORIGINAL_FILE_SIZE;
		goto out;
	}

	//tao aes_context
	aes_ctx = EVP_CIPHER_CTX_new();
	if (aes_ctx == NULL)
	{
		wprintf(L"Loi khong khoi tao duoc ma hoa\n");
		ret = ERR_INIT_AES_CTX;
		goto out;
	}

	//doc file dau vao de ma hoa
	memset(inBuf, 0, MAX_BUFF_LEN);
	memset(outBuf, 0, MAX_BUFF_LEN);
	SHA256_Init(&sha256_ctx);
	outLen = 0;
	while ((inLen = fread(inBuf, 1, MAX_BUFF_LEN, inFile)) > 0)
	{
		//khoi tao, cai dat khoa va IV
		ret = EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_ofb(), NULL, &ivSessionKey[AES_BLOCK_SIZE], ivSessionKey);
		if (ret != 1)
		{
			wprintf(L"Loi khong khoi tao duoc doi tuong ma hoa\n");
			ret = ERR_INIT_AES_CTX;
			goto out;
		}
		SHA256_Update(&sha256_ctx, inBuf, inLen);

		ret = EVP_EncryptUpdate(aes_ctx, outBuf, &len, inBuf, inLen);
		if (ret != 1)
		{
			wprintf(L"Loi khi ma hoa iv va khoa phien\n");
			ret = ERR_ENCRYPT_IV_KEY;
			goto out;
		}
		outLen = len;
		ret = EVP_EncryptFinal_ex(aes_ctx, outBuf + len, &len);
		if (ret != 1)
		{
			wprintf(L"Loi khi ma hoa iv va khoa phien\n");
			ret = ERR_ENCRYPT_IV_KEY;
			goto out;
		}
		outLen += len;
		//ghi du lieu ma vao file
		ret = fwrite(outBuf, 1, outLen, outFile);
		if (ret != outLen)
		{
			wprintf(L"Khong ghi duoc du lieu ma hoa\n");
			ret = ERR_WRITE_ENC_FILE;
			goto out;
		}

	}

	ret = SHA256_Final(sha256sum, &sha256_ctx);

	//ghi ma bam vao file
	if (fwrite_v(outFile, sha256sum, sizeof(sha256sum)) != 0)
	{
		wprintf(L"Khong ghi duoc ma bam\n");
		ret = ERR_WRITE_HASH;
		goto out;
	}


	ret = 0;

out:
	if (inFile) fclose(inFile);
	if (outFile) fclose(outFile);
	if (ret != 0) _wremove(outputFileName);
	if (userPubKey) free(userPubKey);
	if (wrapKey) free(wrapKey);
	if (rsa) RSA_free(rsa);
	if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);
	if (inBuf) free(inBuf);
	if (outBuf) free(outBuf);
	return ret;

}

FFI_PLUGIN_EXPORT int Zalo_DecryptFile(const wchar_t *inputFileName, const wchar_t *outputFileName, unsigned int userID,
	const char *userPrivKey, unsigned int userPrivKeyLen, const char *pass)
{
	int ret = 0;
	FILE *inFile = NULL, *outFile = NULL;
	SHA256_CTX sha256_ctx;
	EVP_CIPHER_CTX *aes_ctx = NULL;
	unsigned char sha256sum[SHA256_DIGEST_LENGTH];
	RSA *rsa = NULL;
	unsigned char ivSessionKey[AES_BLOCK_SIZE + AES256_KEY_LENGTH]; //bien dung de luu IV va khoa phien
	unsigned int numUser, i, len, countUser, wrapKeyLen;
	unsigned int readUserID, inLen, outLen, originalFileSize, originalFileExtLen, readSha256sumLen;


	unsigned char *inBuf = NULL, *outBuf = NULL; //[BUFF_READ_LEN];
	char *originalFileExt = NULL;
	unsigned char *wrapKey = NULL;
	unsigned char *readSha256sum = NULL;
	wchar_t *outFullFileName = NULL;



	if (inputFileName == NULL)
		return ERR_BAD_INPUT_FILENAME;
	if (outputFileName == NULL)
		return ERR_BAD_OUTPUT_FILENAME;
	if (userPrivKey == NULL || userPrivKeyLen == 0)
		return ERR_BAD_USER_PRIVKEY;


	inBuf = (unsigned char *)malloc(MAX_BUFF_LEN);
	outBuf = (unsigned char *)malloc(MAX_BUFF_LEN);
	if (inBuf == NULL || outBuf == NULL)
	{
		wprintf(L"Khong khoi tao duoc bo nho cho du lieu!");
		ret = ERR_ALLOC_FAILED;
		goto out;
	}


	//doc khoa bi mat nguoi dung
	rsa = NULL;
	rsa = readRSAprivatekey(userPrivKey, userPrivKeyLen, pass);
	if (rsa == NULL)
	{
		wprintf(L"Loi doc khoa bi mat cua user\n");
		ret = ERR_READ_USER_PRIVKEY;
		goto out;
	}

	//doc file dau vao
	ret = _wfopen_s(&inFile, inputFileName, L"rb,ccs=UNICODE");
	if (ret)
	{
		wprintf(L"Co loi khi mo file dau vao: %s\n", inputFileName);
		return ERR_OPEN_INPUT_FILE;
	}

	//doc so luong user
	if (fread(&numUser, 1, sizeof(int), inFile) != sizeof(int))
	{
		wprintf(L"Co loi khi doc so luong user\n");
		ret = ERR_READ_NUM_USER;
		goto out;
	}
	//doc dinh dang file ro ban dau
	if ((originalFileExt = fread_v(inFile, &originalFileExtLen)) == NULL)
	{
		wprintf(L"Co loi khi doc dinh dang file ban dau\n");
		ret = ERR_READ_ORIGINAL_FILE_EXT;
		goto out;
	}

	// gan dinh dang cho file dau ra
	outFullFileName = (wchar_t *)malloc(wcslen(outputFileName) + originalFileExtLen + 2);
	memset(outFullFileName, 0, wcslen(outputFileName) + originalFileExtLen + 2);
	memcpy(outFullFileName, outputFileName, wcslen(outputFileName));
	memcpy(outFullFileName + wcslen(outputFileName), ".", 1);
	memcpy(outFullFileName + wcslen(outputFileName) + 1, originalFileExt, originalFileExtLen);


	ret = _wfopen_s(&outFile, outFullFileName, L"wb,ccs=UNICODE");
	if (ret)
	{
		wprintf(L"Co loi khi tao file dau ra: %s\n", outFullFileName);
		ret = ERR_OPEN_OUTPUT_FILE;
		goto out;
	}

	//doc va tim ID nguoi dung --> doc wrapKey tuong ung
	countUser = 0;
	for (i = 0; i < numUser; i++)
	{
		//doc ID cua user
		if (fread(&readUserID, 1, sizeof(int), inFile) != sizeof(int))
		{
			wprintf(L"Khong doc duoc ID nguoi dung\n");
			ret = ERR_READ_USER_ID;
			goto out;
		}

		if (wrapKey) free(wrapKey);
		wrapKey = fread_v(inFile, &wrapKeyLen);
		if (wrapKeyLen == 0)
		{
			wprintf(L"Co loi khi doc WrapKey\n");
			ret = ERR_READ_WRAPKEY;
			goto out;
		}

		//so sanh ID cua user
		if (readUserID == userID)
		{
			//giai ma lay khoa va IV
			memset(ivSessionKey, 0, sizeof(ivSessionKey));
			ret = RSA_private_decrypt(wrapKeyLen, wrapKey, ivSessionKey, rsa, RSA_PKCS1_OAEP_PADDING);
			if (ret == -1)
			{
				wprintf(L"Khong giai ma duoc IV va khoa phien\n");
				ret = ERR_DECRYPT_IV_KEY;
				goto out;
			}
			else
				countUser++;

		}

	}

	if (countUser == 0)
	{
		wprintf(L"Khong tim thay WrapKey tuong ung voi user\n");
		ret = ERR_WRAPKEY_NOT_FOUND;
		goto out;
	}


	//doc dung luong file ban dau
	if (fread(&originalFileSize,  1, sizeof(int), inFile) != sizeof(int))
	{
		wprintf(L"Co loi khi doc dung luong file ban dau\n");
		ret = ERR_READ_ORIGINAL_FILE_SIZE;
		goto out;
	}

	//tao aes_context
	aes_ctx = EVP_CIPHER_CTX_new();
	if (aes_ctx == NULL)
	{
		wprintf(L"Loi khong khoi tao duoc ma hoa\n");
		ret = ERR_INIT_AES_CTX;
		goto out;
	}

	//doc file dau vao de giai ma
	memset(inBuf, 0, MAX_BUFF_LEN);
	memset(outBuf, 0, MAX_BUFF_LEN);
	SHA256_Init(&sha256_ctx);
	while (originalFileSize > 0)
	{
		inLen = (originalFileSize < MAX_BUFF_LEN) ? originalFileSize : MAX_BUFF_LEN;
		if (inLen != fread(inBuf, 1, inLen, inFile))
		{
			wprintf(L"Loi khong doc duoc du lieu tu file\n");
			ret = ERR_READ_INPUT_FILE;
			goto out;
		}
		originalFileSize -= inLen;
		//khoi tao, cai dat khoa va IV
		ret = EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_ofb(), NULL, &ivSessionKey[AES_BLOCK_SIZE], ivSessionKey);
		if (ret != 1)
		{
			wprintf(L"Loi khong khoi tao duoc doi tuong ma hoa\n");
			ret = ERR_INIT_AES_CTX;
			goto out;
		}

		// giai ma du lieu
		ret = EVP_DecryptUpdate(aes_ctx, outBuf, &len, inBuf, inLen);
		if (ret != 1)
		{
			wprintf(L"Loi khi ma hoa iv va khoa phien\n");
			ret = ERR_ENCRYPT_IV_KEY;
			goto out;
		}
		outLen = len;
		ret = EVP_DecryptFinal_ex(aes_ctx, outBuf + len, &len);
		if (ret != 1)
		{
			wprintf(L"Loi khi ma hoa iv va khoa phien\n");
			ret = ERR_ENCRYPT_IV_KEY;
			goto out;
		}
		outLen += len;


		SHA256_Update(&sha256_ctx, outBuf, outLen);

		//ghi du lieu giai ma vao file
		ret = fwrite(outBuf, 1, outLen, outFile);
		if (ret != outLen)
		{
			wprintf(L"Khong ghi duoc du lieu giai ma\n");
			ret = ERR_WRITE_DEC_FILE;
			goto out;
		}
	}
	SHA256_Final(sha256sum, &sha256_ctx);

	//doc ma bam
	readSha256sum = fread_v(inFile, &readSha256sumLen);
	if (readSha256sum == NULL)
	{
		wprintf(L"Co loi khi doc ma bam\n");
		ret = ERR_READ_HASH;
		goto out;
	}

	//kiem tra ma bam
	if (memcmp(readSha256sum, sha256sum, sizeof(sha256sum)) != 0)
	{
		wprintf(L"Loi xac thuc ma bam, file da bi sua doi\n");
		ret = ERR_HASH_INVALID;
		goto out;
	}

	ret = 0;
out:
	if (inFile) fclose(inFile);
	if (outFile) fclose(outFile);
	if (ret != 0) _wremove(outputFileName);
	if (originalFileExt) free(originalFileExt);
	if (wrapKey) free(wrapKey);
	if (inBuf) free(inBuf);
	if (outBuf) free(outBuf);
	if (outFullFileName) free(outFullFileName);
	if (readSha256sum) free(readSha256sum);
	if (rsa) RSA_free(rsa);
	if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);
	return ret;
}


FFI_PLUGIN_EXPORT int Zalo_ChangePrivKeyPass(const char *inPrivKey, unsigned int inPrivKeyLen, const char *oldPass,
	char *outPrivKey, unsigned int *outPrivKeyLen, unsigned int outPrivKeyMaxLen, const char *newPass)
{
	RSA *rsa = NULL;
	int ret;


	if (inPrivKey == NULL || inPrivKeyLen == 0)
		return ERR_BAD_USER_PRIVKEY;
	if (outPrivKey == NULL || outPrivKeyMaxLen == 0)
		return ERR_BAD_USER_PRIVKEY;
	//doc private key dau vao
	rsa = readRSAprivatekey(inPrivKey, inPrivKeyLen, oldPass);
	if (rsa == NULL)
	{
		wprintf(L"Mat khau cu khong dung\n");
		return ERR_READ_USER_PRIVKEY;
	}


	ret = writeRSAprivatekey(rsa, outPrivKey, outPrivKeyLen, outPrivKeyMaxLen, newPass);
	if (ret != 0)
	{
		wprintf(L"Co loi khi doi mat khau Private key\n");
	}
	if (rsa) RSA_free(rsa);
	return ret;
}

/**
* Ghi du lieu tu buf vao str duoi dang hex
* Ghi do dai buf
* Ghi mang buf
*/

static int writeCharToHex(char *str, const unsigned char *buf, unsigned int lenbuf)
{
	int ret;
	unsigned int i, offset = 0;
	ret = sprintf(str + offset, "%08X", lenbuf);
	if (ret < 0)
		return -1;
	offset += ret;
	for (i = 0; i < lenbuf; i++)
	{
		ret = sprintf(str + offset, "%02X", (int)((char *)buf[i]));
		if (ret < 0)
			return -1;
		offset += ret;
	}


	return offset;
}

/**
* Doc so tu chuoi hex
*/
static int readNumFromHex(const char *str, int *number)
{
	char temp[32] = { 0 };
	unsigned int offset = 0;
	memcpy(temp, str, 8);
	offset += 8;
	*number = strtol(temp, 0, 16);
	return offset;
}

/**
* Doc mang char tu chuoi Hex
* Doc do dai mang buf
* Doc mang buf
*/
static int readCharFromHex(const char *hexStr,
	unsigned char *buf, unsigned int *bufLen, unsigned int bufMaxLen)
{
	unsigned int i,j, offset = 0;
	char *hexStrPtr;
	hexStrPtr = (char*)hexStr;
	//doc do dai buf
	offset += readNumFromHex(hexStrPtr, bufLen);
	if (*bufLen == 0)
		return 0;
	if (*bufLen > bufMaxLen)
		return 0;
	hexStrPtr = (char*)(hexStr + offset);
	for (i = 0, j = 0; i < *bufLen; i++, j += 2)
		buf[i] = (hexStrPtr[j] % 32 + 9) % 25 * 16 + (hexStrPtr[j + 1] % 32 + 9) % 25;
	offset += *bufLen * 2;
	return offset;

}

FFI_PLUGIN_EXPORT int Zalo_EncryptMessage(const unsigned char *inMes, unsigned int inMesLen,
	unsigned char *outMes, unsigned int *outMesLen, unsigned int outMesMaxLen,
	unsigned int *listUserID, const char *listUserPubKey, unsigned int numUser)
{
	int ret;
	unsigned int i, j, k, countUser, wrapKeyLen, outLen, len, listUserPubKeyLen;
	unsigned int userID, outMesOffset = 0;
	SHA256_CTX sha256_ctx;
	EVP_CIPHER_CTX *aes_ctx = NULL;
	unsigned char sha256sum[SHA256_DIGEST_LENGTH];
	RSA *rsa = NULL;

	unsigned char ivSessionKey[AES_BLOCK_SIZE + AES256_KEY_LENGTH]; //bien dung de luu IV va khoa phien
	unsigned char *userPubKey = NULL;
	unsigned char *wrapKey = NULL;
	unsigned char *outBuf = NULL; //[BUFF_READ_LEN];
	char temp[32] = { 0 };

	if (inMes == NULL || inMesLen == 0)
		return ERR_BAD_INPUT_MESSAGE;
	if (outMes == NULL || outMesMaxLen == 0)
		return ERR_BAD_OUTPUT_MESSAGE;
	if (listUserPubKey == NULL)
		return ERR_BAD_LIST_USERPUBKEY;
	if (listUserID == NULL)
		return ERR_BAD_LIST_USERID;

	memset(outMes, 0, outMesMaxLen);

	//truyen tam so user vao mes dau rra
	ret = sprintf(outMes + outMesOffset, "%08X", numUser);
	if (ret < 0)
	{
		wprintf(L"Khong ghi duoc so luong user\n");
		ret = ERR_WRITE_NUM_USER;
		goto out;
	}
	outMesOffset += ret; //dich con tro
	if (outMesOffset > outMesMaxLen)
	{
		ret = ERR_BAD_OUTPUT_MESSAGE_LENGTH;
		goto out;
	}
	//khoi tao bo nho cho du lieu
	userPubKey = (unsigned char *)malloc(MAX_PUBKEY_LEN);
	wrapKey = (unsigned char *)malloc(MAX_RSA_MODULUS_BYTE);
	outBuf = (unsigned char *)malloc(inMesLen);
	if (userPubKey == NULL || wrapKey == NULL || outBuf == NULL)
	{
		wprintf(L"Khong khoi tao duoc bo nho cho du lieu!");
		ret = ERR_ALLOC_FAILED;
		goto out;
	}
	//sinh ngau nhien IV va khoa
	ret = RAND_bytes(ivSessionKey, AES_BLOCK_SIZE + AES256_KEY_LENGTH);
	if (ret != 1)
	{
		wprintf(L" Loi khi sinh IV va khoa phien \n");
		ret = ERR_GENERATE_IV_KEY;
		goto out;
	}


	//doc chung thu so cua nguoi dung
	listUserPubKeyLen = strlen(listUserPubKey);
	j = 0;
	countUser = 0;
	for (i = 0, k = 0; i <= listUserPubKeyLen && k < numUser; i++)
	{
		if (listUserPubKey[i] != ';' && i < listUserPubKeyLen && j < MAX_PUBKEY_LEN)
		{
			if (j == 0)
				memset(userPubKey, 0, MAX_PUBKEY_LEN);
			userPubKey[j++] = listUserPubKey[i];
		}
		else
		{
			rsa = NULL;
			rsa = readRSApubkey(userPubKey, j);
			if (rsa == NULL)
			{
				wprintf(L"Khong doc duoc khoa cong khai cua nguoi dung\n");
				ret = ERR_READ_USER_PUBKEY;
				continue; //tiep tuc doc cert tiep theo
			}


			//ghi ID cua nguoi dung
			userID = listUserID[k];
			ret = sprintf(outMes + outMesOffset, "%08X", userID);
			if (ret < 0)
			{
				wprintf(L"Khong ghi duoc ID nguoi dung\n");
				ret = ERR_WRITE_USER_ID;
				continue;
			}
			outMesOffset += ret; //dich con tro
			if (outMesOffset > outMesMaxLen)
			{
				ret = ERR_BAD_OUTPUT_MESSAGE_LENGTH;
				goto out;
			}

			j = 0;
			k++;

			//ma hoa IV va khoa phien
			memset(wrapKey, 0, MAX_RSA_MODULUS_BYTE);
			ret = RSA_public_encrypt(sizeof(ivSessionKey), ivSessionKey, wrapKey, rsa, RSA_PKCS1_OAEP_PADDING);
			if (ret == -1)
			{
				wprintf(L"Khong ma hoa duoc IV va khoa phien\n ");
				ret = ERR_ENCRYPT_IV_KEY;
				continue;
			}
			wrapKeyLen = ret;
			//ghi WrapKey vao tin nhan dau ra
			ret = writeCharToHex(outMes + outMesOffset, wrapKey, wrapKeyLen);

			if (ret < 0)
			{
				wprintf(L"Khong ghi duoc wrapkey\n");
				ret = ERR_WRITE_WRAPKEY;
				continue;
			}
			else
			{
				countUser++;
			}
			outMesOffset += ret; //dich con tro
			if (outMesOffset > outMesMaxLen)
			{
				ret = ERR_BAD_OUTPUT_MESSAGE_LENGTH;
				goto out;
			}
		}
	}

	if (countUser == 0)
	{
		wprintf(L"Khong doc duoc chung thu so nao cua user\n");
		ret = ERR_READ_ALL_USER_PUBKEY;
		goto out;
	}

	//ghi lai so luong user thuc te len dau tin nhan dau ra
	ret = sprintf(temp, "%08X", countUser);
	if (ret < 0)
	{
		wprintf(L"Khong ghi duoc so luong user\n");
		ret = ERR_WRITE_NUM_USER;
		goto out;
	}
	memcpy(outMes, temp, ret);


	//tao aes_context
	aes_ctx = EVP_CIPHER_CTX_new();
	if (aes_ctx == NULL)
	{
		wprintf(L"Loi khong khoi tao duoc ma hoa\n");
		ret = ERR_INIT_AES_CTX;
		goto out;
	}

	//ma hoa tin nhan
	SHA256_Init(&sha256_ctx);
	outLen = 0;
	len = 0;
	//khoi tao, cai dat khoa va IV
	ret = EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_ofb(), NULL, &ivSessionKey[AES_BLOCK_SIZE], ivSessionKey);
	if (ret != 1)
	{
		wprintf(L"Loi khong khoi tao duoc doi tuong ma hoa\n");
		ret = ERR_INIT_AES_CTX;
		goto out;
	}
	SHA256_Update(&sha256_ctx, inMes, inMesLen);

	ret = EVP_EncryptUpdate(aes_ctx, outBuf, &len, inMes, inMesLen);
	if (ret != 1)
	{
		wprintf(L"Loi khi ma hoa iv va khoa phien\n");
		ret = ERR_ENCRYPT_IV_KEY;
		goto out;
	}
	outLen = len;
	ret = EVP_EncryptFinal_ex(aes_ctx, outBuf + len, &len);
	if (ret != 1)
	{
		wprintf(L"Loi khi ma hoa iv va khoa phien\n");
		ret = ERR_ENCRYPT_IV_KEY;
		goto out;
	}
	outLen += len;
	//ghi du lieu ma ra tin nhan dau ra
	ret = writeCharToHex(outMes + outMesOffset, outBuf, outLen);
	if (ret < 0)
	{
		wprintf(L"Khong ghi duoc ban ma tin nhan\n");
		ret = ERR_WRITE_ENC_MESSAGE;
		goto out;
	}
	outMesOffset += ret; //dich con tro
	if (outMesOffset > outMesMaxLen)
	{
		ret = ERR_BAD_OUTPUT_MESSAGE_LENGTH;
		goto out;
	}
	SHA256_Final(sha256sum, &sha256_ctx);



	//ghi ma bam ra tin nhan dau ra
	ret = writeCharToHex(outMes + outMesOffset, sha256sum, sizeof(sha256sum));
	if (ret < 0)
	{
		wprintf(L"Khong ghi duoc ma bam\n");
		ret = ERR_WRITE_HASH;
		goto out;
	}

	outMesOffset += ret; //dich con tro
	if (outMesOffset > outMesMaxLen)
	{
		ret = ERR_BAD_OUTPUT_MESSAGE_LENGTH;
		goto out;
	}
	*outMesLen = outMesOffset;
	ret = 0;

out:

	if (userPubKey) free(userPubKey);
	if (wrapKey) free(wrapKey);
	if (outBuf) free(outBuf);
	if (rsa) RSA_free(rsa);
	if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);

	return ret;
}

FFI_PLUGIN_EXPORT int Zalo_DecryptMessage(const unsigned char* inMes, unsigned int inMesLen,
	unsigned char* outMes, unsigned int* outMesLen, unsigned int outMesMaxLen,
	unsigned int userID, const char* userPrivKey, unsigned int userPrivKeyLen, const char* pass)
{
	int ret = 0;

	SHA256_CTX sha256_ctx;
	EVP_CIPHER_CTX* aes_ctx = NULL;
	unsigned char sha256sum[SHA256_DIGEST_LENGTH];
	RSA* rsa = NULL;
	unsigned char ivSessionKey[AES_BLOCK_SIZE + AES256_KEY_LENGTH]; //bien dung de luu IV va khoa phien
	unsigned int numUser, i, len, countUser, wrapKeyLen;
	unsigned int readUserID, inLen, readSha256sumLen;
	unsigned int inMesOffset = 0;


	unsigned char* inBuf = NULL; //[BUFF_READ_LEN];
	unsigned char* wrapKey = NULL;
	unsigned char readSha256sum[SHA256_DIGEST_LENGTH];


	memset(outMes, 0, outMesMaxLen);

	if (inMes == NULL || inMesLen == 0)
		return ERR_BAD_INPUT_MESSAGE;
	if (outMes == NULL || outMesMaxLen == 0)
		return ERR_BAD_OUTPUT_MESSAGE;
	if (userPrivKey == NULL || userPrivKeyLen == 0)
		return ERR_BAD_USER_PRIVKEY;


	inBuf = (unsigned char*)malloc(MAX_BUFF_LEN);
	wrapKey = (unsigned char*)malloc(MAX_RSA_MODULUS_BYTE);
	if (wrapKey == NULL || inBuf == NULL)
	{
		wprintf(L"Khong khoi tao duoc bo nho cho du lieu!");
		ret = ERR_ALLOC_FAILED;
		goto out;
	}


	//doc khoa bi mat nguoi dung
	rsa = NULL;
	rsa = readRSAprivatekey(userPrivKey, userPrivKeyLen, pass);
	if (rsa == NULL)
	{
		wprintf(L"Loi doc khoa bi mat cua user\n");
		ret = ERR_READ_USER_PRIVKEY;
		goto out;
	}

	//doc so luong user
	numUser = 0;
	inMesOffset += readNumFromHex(inMes + inMesOffset, &numUser);
	if (inMesOffset > inMesLen)
	{
		ret = ERR_BAD_INPUT_MESSAGE_LENGTH;
		goto out;
	}
	if (numUser == 0)
	{
		wprintf(L"Co loi khi doc so luong user\n");
		ret = ERR_READ_NUM_USER;
		goto out;
	}

	//doc va tim ID nguoi dung --> doc wrapKey tuong ung
	countUser = 0;
	for (i = 0; i < numUser; i++)
	{
		//doc ID cua user
		readUserID = 0;
		inMesOffset += readNumFromHex(inMes + inMesOffset, &readUserID);
		if (inMesOffset > inMesLen)
		{
			ret = ERR_BAD_INPUT_MESSAGE_LENGTH;
			goto out;
		}
		if (readUserID == 0)
		{
			wprintf(L"Khong doc duoc ID nguoi dung\n");
			ret = ERR_READ_USER_ID;
			goto out;
		}

		//doc wrapkey
		memset(wrapKey, 0, MAX_RSA_MODULUS_BYTE);
		ret = readCharFromHex(inMes + inMesOffset, wrapKey, &wrapKeyLen, MAX_RSA_MODULUS_BYTE);
		if (ret == 0)
		{
			wprintf(L"Co loi khi doc WrapKey\n");
			ret = ERR_READ_WRAPKEY;
			goto out;
		}
		inMesOffset += ret; //dich con tro
		if (inMesOffset > inMesLen)
		{
			ret = ERR_BAD_INPUT_MESSAGE_LENGTH;
			goto out;
		}

		//so sanh ID cua user
		if (readUserID == userID)
		{
			//giai ma lay khoa va IV
			memset(ivSessionKey, 0, sizeof(ivSessionKey));
			ret = RSA_private_decrypt(wrapKeyLen, wrapKey, ivSessionKey, rsa, RSA_PKCS1_OAEP_PADDING);
			if (ret == -1)
			{
				wprintf(L"Khong giai ma duoc IV va khoa phien\n");
				ret = ERR_DECRYPT_IV_KEY;
				goto out;
			}
			else
				countUser++;

		}

	}

	if (countUser == 0)
	{
		wprintf(L"Khong tim thay WrapKey tuong ung voi user\n");
		ret = ERR_WRAPKEY_NOT_FOUND;
		goto out;
	}


	//tao aes_context
	aes_ctx = EVP_CIPHER_CTX_new();
	if (aes_ctx == NULL)
	{
		wprintf(L"Loi khong khoi tao duoc ma hoa\n");
		ret = ERR_INIT_AES_CTX;
		goto out;
	}

	//doc du lieu dau vao de giai ma
	ret = readCharFromHex(inMes + inMesOffset, inBuf, &inLen, MAX_BUFF_LEN);
	if (ret == 0)
	{
		wprintf(L"Loi khong doc duoc ban ma tin nhan\n");
		ret = ERR_READ_ENC_MESSAGE;
		goto out;
	}
	inMesOffset += ret; //dich con tro
	if (inMesOffset > inMesLen)
	{
		ret = ERR_BAD_INPUT_MESSAGE_LENGTH;
		goto out;
	}
	SHA256_Init(&sha256_ctx);
	//khoi tao, cai dat khoa va IV
	ret = EVP_DecryptInit_ex(aes_ctx, EVP_aes_256_ofb(), NULL, &ivSessionKey[AES_BLOCK_SIZE], ivSessionKey);
	if (ret != 1)
	{
		wprintf(L"Loi khong khoi tao duoc doi tuong ma hoa\n");
		ret = ERR_INIT_AES_CTX;
		goto out;
	}

	// giai ma du lieu
	ret = EVP_DecryptUpdate(aes_ctx, outMes, &len, inBuf, inLen);
	if (ret != 1)
	{
		wprintf(L"Loi khi ma hoa iv va khoa phien\n");
		ret = ERR_ENCRYPT_IV_KEY;
		goto out;
	}
	*outMesLen = len;
	ret = EVP_DecryptFinal_ex(aes_ctx, outMes + len, &len);
	if (ret != 1)
	{
		wprintf(L"Loi khi ma hoa iv va khoa phien\n");
		ret = ERR_ENCRYPT_IV_KEY;
		goto out;
	}
	*outMesLen += len;
	if (*outMesLen > outMesMaxLen)
	{
		ret = ERR_BAD_OUTPUT_MESSAGE_LENGTH;
		goto out;
	}

	SHA256_Update(&sha256_ctx, outMes, *outMesLen);

	SHA256_Final(sha256sum, &sha256_ctx);

	//doc ma bam
	ret = readCharFromHex(inMes + inMesOffset, readSha256sum, &readSha256sumLen, sizeof(readSha256sum));
	if (ret == 0)
	{
		wprintf(L"Co loi khi doc ma bam\n");
		ret = ERR_READ_HASH;
		goto out;
	}
	inMesOffset += ret; //dich con tro
	if (inMesOffset > inMesLen)
	{
		ret = ERR_BAD_INPUT_MESSAGE_LENGTH;
		goto out;
	}

	//kiem tra ma bam
	if (memcmp(readSha256sum, sha256sum, sizeof(sha256sum)) != 0)
	{
		wprintf(L"Loi xac thuc ma bam, file da bi sua doi\n");
		ret = ERR_HASH_INVALID;
		goto out;
	}

	ret = 0;
out:

	if (wrapKey) free(wrapKey);
	if (inBuf) free(inBuf);
	if (rsa) RSA_free(rsa);
	if (aes_ctx) EVP_CIPHER_CTX_free(aes_ctx);
	return ret;
}

FFI_PLUGIN_EXPORT const char *Zalo_Error(int errNum)
{
	return error_str(errNum);
}