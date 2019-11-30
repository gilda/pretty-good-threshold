#include "aes.h"

// TODO make sure key is 256 bit and iv is 128 bit
namespace AES{
	int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext){
		EVP_CIPHER_CTX *ctx;
		int len;
		int ciphertext_len;
		
		// create and initialise the context
		if(!(ctx = EVP_CIPHER_CTX_new()))
		
		// initialise the encryption operation
		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))

		// provide the message to be encrypted, and obtain the encrypted output
		if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		ciphertext_len = len;

		// finalise the encryption
		if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		ciphertext_len += len;

		// clean up
		EVP_CIPHER_CTX_free(ctx);

		return ciphertext_len;
	}


	int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext){
		EVP_CIPHER_CTX *ctx;
		int len;
		int plaintext_len;

		// create and initialise the context
		if(!(ctx = EVP_CIPHER_CTX_new()))

		// initialise the decryption operation
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))

		// provide the message to be decrypted, and obtain the plaintext output
		if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		plaintext_len = len;

		// finalise the decryption
		if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		plaintext_len += len;

		// clean up
		EVP_CIPHER_CTX_free(ctx);

		return plaintext_len;
	}
}
