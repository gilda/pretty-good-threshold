#pragma once
#include <string>
#include <openssl/ecdh.h>
#include "../aes/aes.h"
#include "../ecdh/ecdh.h"

class ECIES{
	public:
		ECIES(EC_KEY *key, EC_KEY *pkey);

		int encrypt(std::string plaintext,
                	std::string aad,
                	unsigned char *iv, int iv_len,
                	unsigned char *ciphertext,
                	unsigned char *tag);
		
		std::string decrypt(unsigned char *ciphertext,
							int ciphertext_len,
                			std::string aad,
                			unsigned char *tag,
                			unsigned char *iv, int iv_len);
	private:
		EC_KEY *key;
		EC_KEY *pkey;
};
