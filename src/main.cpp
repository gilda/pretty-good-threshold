#include <iostream>
#include "ssss/ssss.h"
#include "vss/vss.h"
#include "aes/aes.h"
#include "util/util.h"

int main(){
	initOpenSSL();

	BIGNUM *a = BN_new();
	BN_hex2bn(&a, "17263ba6bff76");

	SSSS gilda = SSSS(3, 5, a);
	std::vector<Share> points = gilda.getShares();
	
	for(auto it = points.begin(); it != points.end(); it++){
		printf("x = %s, y = %s\n", BN_bn2hex(it->x), BN_bn2hex(it->y));
	}

	printf("f(0) = %s\n\n", BN_bn2hex(gilda.recoverSecret(points)));

	VSS feld = VSS(4, 5, BN_dup(a));
	Share fake;
	fake.x = BN_new();
	fake.y = BN_new();
	BN_one(fake.y);
	feld.verifyShare(fake);

	unsigned char ctext[((std::string("gilda is very smart!").length() / 16 + 1)*16)];
	unsigned char tag[16];
	unsigned char *key = randomPrivateBytes(32);
	unsigned char *iv = randomPrivateBytes(12);
	printf("key: %s\niv: %s\n", encodeHex(key, 32).c_str(), encodeHex(iv, 12).c_str());
	int ctextlen = AES::gcm_encrypt("gilda is very smart!", "", key, iv, 12, ctext, tag);
	printf("ctextlen: %d\nctext: %s\n", ctextlen, encodeHex(key, ctextlen).c_str());
	std::string obt = AES::gcm_decrypt(ctext, ctextlen, "", tag, key, iv, 12);
	printf("obt: %s\n", obt.c_str());

	cleanupOpenSSL();
	return 0;
}
