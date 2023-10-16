#include "error.h"
#include <stdlib.h>

struct enum_specs
{
	int code;
	const char *name;
};

static struct enum_specs error_list[] =
{
	{ ERR_OPEN_INPUT_FILE 				 , " Khong mo duoc file nguon" },
	{ ERR_OPEN_OUTPUT_FILE 				 , " Khong mo duoc file dich" },

	{ ERR_READ_USER_PUBKEY				 , " Khong doc duoc khoa cong khai cua user" },
	{ ERR_BAD_INPUT_FILENAME				 , " Chua truyen vao ten file dau vao" },
	{ ERR_BAD_OUTPUT_FILENAME			 , " Chua truyen vao ten file dau ra" },
	{ ERR_RANDOM_INIT						 , " Khong khoi tao duoc nguon ngau nhien" },
	{ ERR_GENERATE_IV_KEY					 , " Khong sinh duoc IV va khoa phien" },
	{ ERR_ENCRYPT_IV_KEY					 , " Khong ma hoa duoc IV va khoa phien" },
	{ ERR_ALLOC_FAILED					 , " Khong khoi tao duoc bo nho cho du lieu" },
	{ ERR_WRITE_WRAPKEY					 , " Khong ghi duoc WrapKey" },
	{ ERR_WRITE_ENC_FILE					 , " Khong ghi duoc file ma" },
	{ ERR_WRITE_HASH  , " Khong ghi duoc ma bam" },
	{ ERR_WRITE_INPUT_FILE_EXT    		, " Khong ghi duoc dinh dang file dau vao" },
	{ ERR_BAD_LIST_USERPUBKEY			 , " Chua truyen danh sach pubkey user" },
	{ ERR_BAD_USER_PRIVKEY				 , " Chua truyen khoa bi mat cua user" },
	{ ERR_READ_USER_PRIVKEY				 , " Khong doc duoc khoa bi mat cua user" },
	{ ERR_READ_ALL_USER_PUBKEY			 , " Khong ky duoc pubkey nao, khi gui cho nhieu nguoi nhan" },
	{ ERR_READ_NUM_USER					 , " Khong doc duoc so luong user" },
	{ ERR_READ_ORIGINAL_FILE_EXT    		 , " Khong ghi duoc dinh dang file dau vao" },
	{ ERR_READ_WRAPKEY		    		 , " Khong doc duoc WrapKey" },
	{ ERR_DECRYPT_IV_KEY					 , " Khong giai ma duoc IV va khoa phien" },
	{ ERR_WRITE_USER_ID					 , " Khong ghi duoc so ID user" },
	{ ERR_READ_USER_ID					 , " Khong doc duoc ID user" },
	{ ERR_WRAPKEY_NOT_FOUND		    	 , " Khong tim thay WrapKey" },
	{ ERR_WRITE_ORIGINAL_FILE_SIZE		 , " Khong ghi duoc dung luong file ban dau" },
	{ ERR_READ_ORIGINAL_FILE_SIZE			 , " Khong doc duoc dung luong file ban dau" },
	{ ERR_WRITE_DEC_FILE					 , " Khong ghi duoc file giai ma" },
	{ ERR_READ_HASH						 , " Khong doc duoc ma bam" },
	{ ERR_HASH_INVALID					 , " Loi xac thuc ma bam" },
	{ ERR_INIT_AES_CTX					 , " Khong khoi tao duoc doi tuong ma hoa" },
	{ ERR_READ_INPUT_FILE 				 , " Khong doc duoc file nguon" },
	{ ERR_BAD_LIST_USERID					 , " Chua truyen danh sach ID user" },
	{ ERR_CHANGE_PRIVKEY_PASS				 , " Khong doi duoc mat khau Private key" },
	{ ERR_BAD_PRIVKEY_LENGTH				, " Do dai du lieu private key khong hop le" },
	{ ERR_WRITE_NUM_USER					 , " Khong ghi duoc so luong user" },

	{ ERR_BAD_INPUT_MESSAGE				 , " Chua truyen tin nhan dau vao" },
	{ ERR_BAD_OUTPUT_MESSAGE				 , " Chua truyen tin nhan dau ra" },
	{ ERR_BAD_OUTPUT_MESSAGE_LENGTH		 , " Do dai du lieu tin nhan dau ra khong du" },
	{ ERR_BAD_INPUT_MESSAGE_LENGTH		 , " Do dai du lieu tin nhan dau vao khong du" },

	{ ERR_WRITE_ENC_MESSAGE				 , " Khong ghi duoc ban ma tin nhan" },
	{ ERR_READ_ENC_MESSAGE				 , " Khong doc duoc ban ma tin nhan" }
};


const char *error_str(int error_code)
{
	unsigned int i;
	unsigned int size = sizeof(error_list) / sizeof(struct enum_specs);

	for (i = 0; i < size; i++)
		if (error_list[i].code == error_code)
			return error_list[i].name;
	return NULL;
}