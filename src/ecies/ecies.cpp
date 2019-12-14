#include "ecies.h"

ECIES::ECIES(EC_KEY *key, EC_KEY *pkey){
	// TODO check validity of keys
	this->key = key;
	this->pkey = pkey;
}

int ECIES::encrypt(std::string plaintext,
            std::string aad,
            unsigned char *iv, int iv_len,
            unsigned char *ciphertext,
            unsigned char *tag){

	// TODO remove 256/8 to define
	unsigned char *key = ECDH::computeKey(this->key, this->pkey, 256/8);
	return AES::gcm_encrypt(plaintext, aad, key, iv, iv_len, ciphertext, tag);
}

std::string ECIES::decrypt(unsigned char *ciphertext,
						   int ciphertext_len,
          				   std::string aad,
          				   unsigned char *tag,
           				   unsigned char *iv, int iv_len){

	// TODO remove 256/8 to define
	unsigned char *key = ECDH::computeKey(this->key, this->pkey, 256/8);
	return AES::gcm_decrypt(ciphertext, ciphertext_len, aad, tag, key, iv, iv_len);
}
