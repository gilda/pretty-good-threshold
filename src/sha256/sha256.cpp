#include "sha256.h"

unsigned char *HASH::sha256(unsigned char *data, unsigned int len){
	unsigned char *ret = new unsigned char[SHA256_DIGEST_LENGTH];
	
	SHA256_CTX ctx;
	if(SHA256_Init(&ctx) != 1) handleErrors();
	if(SHA256_Update(&ctx, data, len)) handleErrors();
	if(SHA256_Final(ret, &ctx)) handleErrors();
	
	return ret;
}

unsigned char *HASH::sha256(std::string data){
	return HASH::sha256((unsigned char *)data.c_str(), data.length);
}
