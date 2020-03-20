#pragma once
#include <string>
#include <openssl/evp.h>
#include "../util/util.h"

class AESEncrypter{
	private:
		int iv_len;
		unsigned char *key;
		unsigned char *iv;
		unsigned char *tag;
		void prepare();

	public:
		AESEncrypter(unsigned char *key, int iv_len);
		int encrypt(std::string plaintext,
					std::string aad,
					unsigned char *ciphertext);
		void flush();
		unsigned char *getIv();
		unsigned char *getTag();
};

class AESDecrypter{
	private:
		int iv_len;
		unsigned char *key;
		unsigned char *iv;
		unsigned char *tag;

	public:
		AESDecrypter(unsigned char *key, int iv_len);
		std::string decrypt(unsigned char *ciphertext, int ciphertext_len,
                			std::string aad);
		void setIv(unsigned char *iv);
		void setTag(unsigned char *tag);
};

namespace AES{
	int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                	unsigned char *aad, int aad_len,
                	unsigned char *key,
                	unsigned char *iv, int iv_len,
                	unsigned char *ciphertext,
                	unsigned char *tag);

	int gcm_encrypt(std::string plaintext,
                	std::string aad,
                	unsigned char *key,
                	unsigned char *iv, int iv_len,
                	unsigned char *ciphertext,
                	unsigned char *tag);

	int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                	unsigned char *aad, int aad_len,
                	unsigned char *tag,
                	unsigned char *key,
                	unsigned char *iv, int iv_len,
                	unsigned char *plaintext);

	std::string gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                	std::string aad,
                	unsigned char *tag,
                	unsigned char *key,
                	unsigned char *iv, int iv_len);
};
