#include "ecdsa.h"

unsigned char *ECDSA::sign(unsigned char *data, unsigned int len, EC_KEY *key){
	unsigned char *rChar = new unsigned char[64];
	unsigned char *sChar = new unsigned char[64];
	unsigned char *ret = new unsigned char[64*2];

	unsigned char *dgst = HASH::sha256(data, len);
	ECDSA_SIG *sig = ECDSA_do_sign(dgst, SHA256_DIGEST_LENGTH, key);
	if(sig == NULL) handleErrors();

	// TODO check errors
	const BIGNUM *r = BN_new();
	const BIGNUM *s = BN_new();
	ECDSA_SIG_get0(sig, &r, &s);

	rChar = (unsigned char *)BN_bn2hex(r);
	sChar = (unsigned char *)BN_bn2hex(s);
	memcpy(ret, rChar, 64);
	memcpy(ret + 64, sChar, 64);

	// TODO return in unsigned char without hex encoding
	return ret;
}

unsigned char *ECDSA::sign(std::string data, EC_KEY *key){
	return ECDSA::sign((unsigned char *)data.c_str(), data.length(), key);
}

bool ECDSA::verify(unsigned char *data, unsigned int len, EC_KEY *key, unsigned char *signature){
	unsigned char *dgst = HASH::sha256(data, len);
	ECDSA_SIG *sig = ECDSA_SIG_new();
	BIGNUM *r = BN_new();
	BIGNUM *s = BN_new();
	char *rHex = new char[64];
	char *sHex = new char[64];

	// TODO check errors
	// TODO make real unsigned char
	memcpy(rHex, signature, 64);
	memcpy(sHex, signature + 64, 64);
	BN_hex2bn(&r, rHex);
	BN_hex2bn(&s, sHex);

	ECDSA_SIG_set0(sig, r, s);
	int ret = ECDSA_do_verify(dgst, SHA256_DIGEST_LENGTH, sig, key);
	if(ret == -1) handleErrors();

	return ret == 1;
}

bool ECDSA::verify(std::string data, EC_KEY *key, unsigned char *signature){
	return ECDSA::verify((unsigned char *)data.c_str(), data.length(), key, signature);
}
