#include <iostream>
#include "util/util.h"
#include "ssss/ssss.h"
#include "vss/vss.h"
#include "aes/aes.h"
#include "ecdh/ecdh.h"
#include "ecies/ecies.h"
#include "sha256/sha256.h"
#include "ecdsa/ecdsa.h"


// TODO make sure all keys are OPENSSL_secure_malloc()
// TODO comment aes ecdh ecies
// TODO refactor to two entities ({prover, verifier}, {encrypter, decrypter}, {dealer, player})

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
	std::vector<Share> vssPoints = feld.getShares();
	Share fake;
	fake.x = BN_new();
	fake.y = BN_new();
	BN_set_word(fake.x, 2);
	BN_set_word(fake.y, 2);
	printf("real share #0: %s\n", feld.verifyShare(vssPoints.at(0)) ? "valid share" : "invalid share");
	printf("real share #1: %s\n", feld.verifyShare(vssPoints.at(1)) ? "valid share" : "invalid share");
	printf("real share #2: %s\n", feld.verifyShare(vssPoints.at(2)) ? "valid share" : "invalid share");
	printf("real share #3: %s\n", feld.verifyShare(vssPoints.at(3)) ? "valid share" : "invalid share");
	printf("real share #4: %s\n", feld.verifyShare(vssPoints.at(4)) ? "valid share" : "invalid share");
	printf("fake share: %s\n\n", feld.verifyShare(fake) ? "valid share" : "invalid share");

	// AES-GCM
	std::string aesPtext = "aes works!";
	unsigned char ctext[((aesPtext.length() / 16 + 1)*16)];
	unsigned char *key = randomPrivateBytes(32);
	printf("ptext: %s\n", aesPtext.c_str());
	AESEncrypter encrypter = AESEncrypter(key, 12);
	AESDecrypter decrypter = AESDecrypter(key, 12);
	int ctextlen = encrypter.encrypt(aesPtext, "", ctext);
	printf("ctextlen: %d\nctext: %s\n", ctextlen, encodeHex(ctext, ctextlen).c_str());
	decrypter.setIv(encrypter.getIv());
	decrypter.setTag(encrypter.getTag());
	std::string obt = decrypter.decrypt(ctext, ctextlen, "");
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

	// ECIES
	ECIES test = ECIES(ecKey, peerKey); 
	std::string eciesPtext = "ecies works!";
	unsigned char eciesCtext[((eciesPtext.length() / 16 + 1)*16)];
	unsigned char eciesTag[16];
	unsigned char *eciesIv = randomPrivateBytes(12);
	int eciesCtextlen = test.encrypt(eciesPtext, "", eciesIv, 12, eciesCtext, eciesTag);
	printf("ctextlen: %d\nctext: %s\n", ctextlen, encodeHex(eciesCtext, eciesCtextlen).c_str());
	std::string eciesObt = test.decrypt(eciesCtext, eciesCtextlen, "", eciesTag, eciesIv, 12);
	printf("obt: %s\n\n", eciesObt.c_str());

	// SHA256
	std::string hashedData = "gilda";
	unsigned char *md = HASH::sha256((unsigned char *)hashedData.c_str(), hashedData.length());
	printf("SHA256(\"gilda\") = %s\n", encodeHex(md, SHA256_DIGEST_LENGTH).c_str());

	// ECDSA
	std::string sigData = "gilda";
	unsigned char *sig = ECDSA::sign((unsigned char *)sigData.c_str(), sigData.length(), ecKey);
	printf("signature is: %s\n", (char *)sig);
	printf("signature is: %s\n", ECDSA::verify((unsigned char *)sigData.c_str(), sigData.length(), ecKey, sig) ? "valid" : "invalid");

	// DKG

	cleanupOpenSSL();
	return 0;
}
