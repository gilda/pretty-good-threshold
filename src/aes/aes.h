#pragma once
#include <string>
#include <openssl/evp.h>
#include "../util/util.h"

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
