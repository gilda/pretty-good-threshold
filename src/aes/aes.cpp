#include "aes.h"

// wrapper for encrypting
// TODO check for NULLs
// TODO calc ctext len by ptext len
AESEncrypter::AESEncrypter(unsigned char *key, int iv_len){
	this->key = key;
	this->iv_len = iv_len;
}

// create random iv and clean tag
void AESEncrypter::prepare(){
	this->iv = randomPrivateBytes(this->iv_len);
	this->tag = new unsigned char[16];
}

// clear iv and tag (redundent)
void AESEncrypter::flush(){
	this->iv = NULL;
	this->tag = NULL;
}

// main function to encrypt
int AESEncrypter::encrypt(std::string plaintext,
                		  std::string aad,
                		  unsigned char *ciphertext){

	this->prepare();
	int ret = AES::gcm_encrypt(plaintext, aad, this->key, this->iv, this->iv_len, ciphertext, this->tag);	
	return ret;
}

unsigned char *AESEncrypter::getIv(){
	return this->iv;
}

unsigned char *AESEncrypter::getTag(){
	return this->tag;
}

// wrapper for decrypting
// TODO check for NULLs
AESDecrypter::AESDecrypter(unsigned char *key, int iv_len){
	this->key = key;
	this->iv_len = iv_len;
}

// main function to decrypt
std::string AESDecrypter::decrypt(unsigned char *ciphertext, int ciphertext_len,
                			std::string aad){

	return AES::gcm_decrypt(ciphertext, ciphertext_len, aad, this->tag, this->key, this->iv, this->iv_len);
}

void AESDecrypter::setIv(unsigned char *iv){
	this->iv = iv;
}

void AESDecrypter::setTag(unsigned char *tag){
	this->tag = tag;
}

// TODO make sure key is 256 bit and iv is 128 bit
namespace AES{
	int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                	unsigned char *aad, int aad_len,
                	unsigned char *key,
                	unsigned char *iv, int iv_len,
                	unsigned char *ciphertext,
                	unsigned char *tag){
		EVP_CIPHER_CTX *ctx;
		int len;
		int ciphertext_len;


		/* Create and initialise the context */
		if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
		
		// validate input
		if(EVP_CIPHER_iv_length(EVP_aes_256_gcm()) != iv_len) return 0;

		/* Initialise the encryption operation. */
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();

		/*
		* Set IV length if default 12 bytes (96 bits) is not appropriate
		*/
		if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) handleErrors();

		/* Initialise key and IV */
		if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

		/*
		* Provide any AAD data. This can be called zero or more times as
		* required
		*/
		if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

		/*
		* Provide the message to be encrypted, and obtain the encrypted output.
		* EVP_EncryptUpdate can be called multiple times if necessary
		*/
		if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
		ciphertext_len = len;

		/*
		* Finalise the encryption. Normally ciphertext bytes may be written at
		* this stage, but this does not occur in GCM mode
		*/
		if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
		ciphertext_len += len;

		/* Get the tag */
		if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) handleErrors();

		/* Clean up */
		EVP_CIPHER_CTX_free(ctx);

		return ciphertext_len;
	}

	int gcm_encrypt(std::string plaintext,
                	std::string aad,
                	unsigned char *key,
                	unsigned char *iv, int iv_len,
                	unsigned char *ciphertext,
                	unsigned char *tag){
		return gcm_encrypt((unsigned char *)plaintext.c_str(), plaintext.length(), (unsigned char *)aad.c_str(), aad.length(), key, iv, iv_len, ciphertext, tag);
	}


	int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                	unsigned char *aad, int aad_len,
                	unsigned char *tag,
                	unsigned char *key,
                	unsigned char *iv, int iv_len,
                	unsigned char *plaintext){
		EVP_CIPHER_CTX *ctx;
		int len;
		int plaintext_len;
		int ret;

		// validate input
		if(EVP_CIPHER_iv_length(EVP_aes_256_gcm()) != iv_len) return 0;

		/* Create and initialise the context */
		if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

		/* Initialise the decryption operation. */
		if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) handleErrors();

		/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
		if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) handleErrors();

		/* Initialise key and IV */
		if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

		/*
		* Provide any AAD data. This can be called zero or more times as
		* required
		*/
		if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();

		/*
		* Provide the message to be decrypted, and obtain the plaintext output.
		* EVP_DecryptUpdate can be called multiple times if necessary
		*/
		if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) handleErrors();
		plaintext_len = len;

		/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
		if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) handleErrors();

		/*
		* Finalise the decryption. A positive return value indicates success,
		* anything else is a failure - the plaintext is not trustworthy.
		*/
		ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

		/* Clean up */
		EVP_CIPHER_CTX_free(ctx);

		if(ret > 0) {
			/* Success */
			plaintext_len += len;
			return plaintext_len;
		} else {
			/* Verify failed */
			return -1;
		}
	}

	std::string gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                	std::string aad,
                	unsigned char *tag,
                	unsigned char *key,
                	unsigned char *iv, int iv_len){
		// create a buffer big enough
		std::string ret;
		ret.reserve(ciphertext_len);
		
		// TODO throw that it is an invalid tag
		int len = gcm_decrypt(ciphertext, ciphertext_len, (unsigned char *)aad.c_str(), aad.length(), tag, key, iv, iv_len, (unsigned char *)&ret[0]);
		if(len == -1) return "";
		return std::string(ret.c_str()).substr(0, len);
	}
}
