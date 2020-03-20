#pragma once
#include <string>
#include <openssl/ecdh.h>
#include "../aes/aes.h"
#include "../ecdh/ecdh.h"

class ECIES{
	private:
		EC_KEY *key;
		EC_KEY *pkey;
		AESEncrypter *encrypter;
		AESDecrypter *decrypter;
	
	public:
		ECIES(EC_KEY *key, EC_KEY *pkey);

		int encrypt(std::string plaintext,
                	std::string aad,
                	unsigned char *ciphertext);
		
		std::string decrypt(unsigned char *ciphertext,
							int ciphertext_len,
                			std::string aad);

		unsigned char *getIv();
		unsigned char *getTag();
		void setIv(unsigned char *iv);
		void setTag(unsigned char *tag);
};
