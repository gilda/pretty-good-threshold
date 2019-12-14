#include <iostream>
#include "util/util.h"
#include "ssss/ssss.h"
#include "vss/vss.h"
#include "aes/aes.h"
#include "ecdh/ecdh.h"

int main(){
	initOpenSSL();

	// SSSS
	BIGNUM *a = BN_new();
	BN_hex2bn(&a, "17263ba6bff76");

	SSSS gilda = SSSS(3, 5, a);
	std::vector<Share> points = gilda.getShares();
	
	for(auto it = points.begin(); it != points.end(); it++){
		printf("x = %s, y = %s\n", BN_bn2hex(it->x), BN_bn2hex(it->y));
	}

	printf("f(0) = %s\n\n", BN_bn2hex(gilda.recoverSecret(points)));

	// VSS
	VSS feld = VSS(4, 5, BN_dup(a));
	Share fake;
	fake.x = BN_new();
	fake.y = BN_new();
	BN_one(fake.y);
	feld.verifyShare(fake);

	// AES-GCM
	unsigned char ctext[((std::string("gilda is very smart!").length() / 16 + 1)*16)];
	unsigned char tag[16];
	unsigned char *key = randomPrivateBytes(32);
	unsigned char *iv = randomPrivateBytes(12);
	printf("key: %s\niv: %s\n", encodeHex(key, 32).c_str(), encodeHex(iv, 12).c_str());
	int ctextlen = AES::gcm_encrypt("gilda is very smart!", "", key, iv, 12, ctext, tag);
	printf("ctextlen: %d\nctext: %s\n", ctextlen, encodeHex(key, ctextlen).c_str());
	std::string obt = AES::gcm_decrypt(ctext, ctextlen, "", tag, key, iv, 12);
	printf("obt: %s\n\n", obt.c_str());


	// ECDH
	EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_generate_key(ecKey);
	EC_KEY *peerKey = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_generate_key(peerKey);
	unsigned char *secret = ECDH::computeKey(ecKey, peerKey, 256/8);
	unsigned char *secret1 = ECDH::computeKey(ecKey, peerKey, 256/8);
	printf("secret: %s\n", encodeHex(secret, 256/8).c_str());
	printf("secret1: %s\n", encodeHex(secret1, 256/8).c_str());

	cleanupOpenSSL();
	return 0;
}
