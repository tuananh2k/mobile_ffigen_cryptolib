#ifndef ERROR_H
#define ERROR_H
#ifdef __cplusplus 
extern "C" {
#endif 



#define ERR_OPEN_INPUT_FILE 				-1 /**< Khong mo duoc file nguon*/
#define ERR_OPEN_OUTPUT_FILE 				-2 /**< Khong mo duoc file dich*/

#define ERR_READ_USER_PUBKEY				-3 /**< Khong doc duoc khoa cong khai cua user*/
#define ERR_BAD_INPUT_FILENAME				-4 /**< Chua truyen vao ten file dau vao*/
#define ERR_BAD_OUTPUT_FILENAME				-5 /**< Chua truyen vao ten file dau ra*/
#define ERR_RANDOM_INIT						-6 /**< Khong khoi tao duoc nguon ngau nhien*/
#define ERR_GENERATE_IV_KEY					-7 /**< Khong sinh duoc IV va khoa phien*/
#define ERR_ENCRYPT_IV_KEY					-8 /**< Khong ma hoa duoc IV va khoa phien*/
#define ERR_ALLOC_FAILED					-9 /**< Khong khoi tao duoc bo nho cho du lieu*/
#define ERR_WRITE_WRAPKEY					-10 /**< Khong ghi duoc WrapKey*/
#define ERR_WRITE_ENC_FILE					-11 /**< Khong ghi duoc file ma*/
#define ERR_WRITE_HASH						-12 /**< Khong ghi duoc ma bam*/
#define ERR_WRITE_INPUT_FILE_EXT    		-13 /**< Khong ghi duoc dinh dang file dau vao*/
#define ERR_BAD_LIST_USERPUBKEY				-14 /**< Chua truyen danh sach pubkey user*/
#define ERR_BAD_USER_PRIVKEY				-15 /**< Chua truyen khoa bi mat cua user*/
#define ERR_READ_USER_PRIVKEY				-16 /**< Khong doc duoc khoa bi mat cua user*/
#define ERR_READ_ALL_USER_PUBKEY			-17 /**< Khong ky duoc pubkey nao, khi gui cho nhieu nguoi nhan*/
#define ERR_READ_NUM_USER					-18 /**< Khong doc duoc so luong user*/
#define ERR_READ_ORIGINAL_FILE_EXT    		-19 /**< Khong ghi duoc dinh dang file dau vao*/
#define ERR_READ_WRAPKEY		    		-20 /**< Khong doc duoc WrapKey*/
#define ERR_DECRYPT_IV_KEY					-21 /**< Khong giai ma duoc IV va khoa phien*/
#define ERR_WRITE_USER_ID					-22 /**< Khong ghi duoc so ID user*/
#define ERR_READ_USER_ID					-23 /**< Khong doc duoc ID user*/
#define ERR_WRAPKEY_NOT_FOUND		    	-24 /**< Khong tim thay WrapKey*/
#define ERR_WRITE_ORIGINAL_FILE_SIZE		-25 /**< Khong ghi duoc dung luong file ban dau*/
#define ERR_READ_ORIGINAL_FILE_SIZE			-26 /**< Khong doc duoc dung luong file ban dau*/
#define ERR_WRITE_DEC_FILE					-27 /**< Khong ghi duoc file giai ma*/
#define ERR_READ_HASH						-28 /**< Khong doc duoc ma bam*/
#define ERR_HASH_INVALID					-29 /**< Loi xac thuc ma bam*/
#define ERR_INIT_AES_CTX					-30 /**< Khong khoi tao duoc doi tuong ma hoa*/
#define ERR_READ_INPUT_FILE 				-31 /**< Khong doc duoc file nguon*/
#define ERR_BAD_LIST_USERID					-32 /**< Chua truyen danh sach ID user*/
#define ERR_CHANGE_PRIVKEY_PASS				-33 /**< Khong doi duoc mat khau Private key*/
#define ERR_BAD_PRIVKEY_LENGTH				-34 /**< Do dai du lieu private key khong hop le*/
#define ERR_WRITE_NUM_USER					-35 /**< Khong ghi duoc so luong user*/

#define ERR_BAD_INPUT_MESSAGE				-36 /**< Chua truyen tin nhan dau vao*/
#define ERR_BAD_OUTPUT_MESSAGE				-37 /**< Chua truyen tin nhan dau ra*/
#define ERR_BAD_OUTPUT_MESSAGE_LENGTH		-38 /**< Do dai du lieu tin nhan dau ra khong du*/
#define ERR_BAD_INPUT_MESSAGE_LENGTH		-39 /**< Do dai du lieu tin nhan dau vao khong du*/

#define ERR_WRITE_ENC_MESSAGE				-40 /**< Khong ghi duoc ban ma tin nhan*/
#define ERR_READ_ENC_MESSAGE				-41 /**< Khong doc duoc ban ma tin nhan*/


	const char *error_str(int error_code);

#ifdef __cplusplus
}
#endif
#endif

