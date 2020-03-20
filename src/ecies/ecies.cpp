#include "ecies.h"

// TODO check for NULL
ECIES::ECIES(EC_KEY *key, EC_KEY *pkey){
	// TODO check validity of keys
	this->key = key;
	this->pkey = pkey;
	// TODO remove 256/8 to define
	unsigned char *dhkey = ECDH::computeKey(this->key, this->pkey, 256/8);
	this->encrypter = new AESEncrypter(dhkey, 12);
	this->decrypter = new AESDecrypter(dhkey, 12);
}

int ECIES::encrypt(std::string plaintext,
            				std::string aad,
            				unsigned char *ciphertext){

	return this->encrypter->encrypt(plaintext, aad, ciphertext);
}

std::string ECIES::decrypt(unsigned char *ciphertext,
						   int ciphertext_len,
          				   std::string aad){

	return this->decrypter->decrypt(ciphertext, ciphertext_len, aad);
}

unsigned char *ECIES::getIv(){
	return this->encrypter->getIv();
}

unsigned char *ECIES::getTag(){
	return this->encrypter->getTag();
}

void ECIES::setIv(unsigned char *iv){
	this->decrypter->setIv(iv);
}


void ECIES::setTag(unsigned char *tag){
	this->decrypter->setTag(tag);
}