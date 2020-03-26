#include <iostream>
#include "../util/util.h"
#include "../ssss/ssss.h"
#include "../vss/vss.h"
#include "../pcommit/pcommit.h"
#include "../aes/aes.h"
#include "../ecdh/ecdh.h"
#include "../ecies/ecies.h"
#include "../sha256/sha256.h"
#include "../ecdsa/ecdsa.h"
#include "../dkg/dkg.h"
#include "../ot/ot.h"


// TODO make sure all keys are OPENSSL_secure_malloc()
// TODO comment aes ecdh ecies
// TODO refactor to two entities ({prover, verifier}, {encrypter, decrypter}, {dealer, player})

int main(){
	initOpenSSL();

	// SSSS
	BIGNUM *a = BN_new();
	BN_hex2bn(&a, "17263ba6bff76");
	SSSSDealer gilda = SSSSDealer(3, 5, a);
	std::vector<Share> points = gilda.getShares();
	SSSSReconstructor gildaConstructor = SSSSReconstructor(3, 5);
	gildaConstructor.addShare(points.at(0));
	gildaConstructor.addShare(points.at(2));
	gildaConstructor.addShare(points.at(4));
	for(auto it = points.begin(); it != points.end(); it++){
		printf("x = %s, y = %s\n", BN_bn2hex(it->x), BN_bn2hex(it->y));
	}
	printf("f(0) = %s\n\n", BN_bn2hex(gildaConstructor.recoverSecret()));

	//PCommitment
	BIGNUM *pcommitValue = BN_new();
	BN_set_word(pcommitValue,3);
	BIGNUM *pcommitRand = BN_new();
	BN_set_word(pcommitRand, 45);
	EC_POINT *commitment = PCommitment::commit(pcommitValue, pcommitRand);
	printf("PCommitment %s\n\n", PCommitment::verify(pcommitValue, pcommitRand, commitment) ? "works" : "is broken");

	// VSS
	VSS feld = VSS(4, 5, BN_dup(a));
	std::vector<VSSShare> vssPoints = feld.getShares();
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	printf("real share #0: %s\n", feld.verifyShare(feld.getCommitments(), vssPoints.at(0)) ? "valid share" : "invalid share");
	printf("real share #1: %s\n", feld.verifyShare(feld.getCommitments(), vssPoints.at(1)) ? "valid share" : "invalid share");
	printf("real share #2: %s\n", feld.verifyShare(feld.getCommitments(), vssPoints.at(2)) ? "valid share" : "invalid share");
	printf("real share #3: %s\n", feld.verifyShare(feld.getCommitments(), vssPoints.at(3)) ? "valid share" : "invalid share");
	printf("real share #4: %s\n", feld.verifyShare(feld.getCommitments(), vssPoints.at(4)) ? "valid share" : "invalid share");
	printf("recovered secret: %s\n", BN_bn2hex(feld.recoverSecret(feld.getShares()).first));
	printf("master vss %s\n\n", EC_POINT_cmp(group, PCommitment::commit(feld.recoverSecret(vssPoints).first, feld.recoverSecret(vssPoints).second), feld.getMasterCommit(), NULL) == 0 ? "works" : "is broken");

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
	int eciesCtextlen = test.encrypt(eciesPtext, "", eciesCtext);
	printf("ctextlen: %d\nctext: %s\n", ctextlen, encodeHex(eciesCtext, eciesCtextlen).c_str());
	test.setIv(test.getIv());
	test.setTag(test.getTag());
	std::string eciesObt = test.decrypt(eciesCtext, eciesCtextlen, "");
	printf("obt: %s\n\n", eciesObt.c_str());

	// SHA256
	std::string hashedData = "gilda";
	unsigned char *md = HASH::sha256((unsigned char *)hashedData.c_str(), hashedData.length());
	printf("SHA256(\"gilda\") = %s\n", encodeHex(md, SHA256_DIGEST_LENGTH).c_str());

	// ECDSA
	std::string sigData = "gilda";
	unsigned char *sig = ECDSA::sign(sigData, ecKey);
	printf("signature is: %s\n", (char *)sig);
	printf("signature is: %s\n\n", ECDSA::verify(sigData, ecKey, sig) ? "valid" : "invalid");

	// DKG
	DKG dkg1 = DKG(0, 3,5);
	DKG dkg2 = DKG(1, 3,5);
	for(unsigned int i = 0; i < dkg1.getCommitments().size(); i++){
		printf("dkg1 poly commitment #%u %s\n", i, EC_POINT_point2hex(group, dkg1.getCommitments().at(i), POINT_CONVERSION_COMPRESSED, NULL));
	}
	for(unsigned int i = 0; i < dkg2.getCommitments().size(); i++){
		printf("dkg2 poly commitment #%u %s\n", i, EC_POINT_point2hex(group, dkg2.getCommitments().at(i), POINT_CONVERSION_COMPRESSED, NULL));
	}
	for(unsigned int i = 0; i < dkg1.getShares().size(); i++){
		//printf("dkg1 share #%u %s %s\n", i, BN_bn2hex(dkg1.getShare(i).secret.y), BN_bn2hex(dkg1.getShare(i).random.y));
		printf("share #%u %s\n", i, DKG::verifyShare(dkg1.getCommitments(), dkg1.getShare(i)) ? "valid" : "invalid");
	}
	for(unsigned int i = 0; i < dkg2.getShares().size(); i++){
		//printf("dkg2 share #%u %s %s\n", i, BN_bn2hex(dkg2.getShare(i).secret.y), BN_bn2hex(dkg2.getShare(i).random.y));
		printf("share #%u %s\n", i, DKG::verifyShare(dkg2.getCommitments(), dkg2.getShare(i)) ? "valid" : "invalid");
	}
	printf("public key is: %s\n\n", EC_POINT_point2hex(group, DKG::getPublicKey(std::vector<EC_POINT *>{dkg1.getPublicKeyCommitment(), dkg2.getPublicKeyCommitment()}), POINT_CONVERSION_COMPRESSED, NULL));
	
	
	// OT
	std::string aVal = "this is a";
	std::string bVal = "this is b";

	OTSender send = OTSender(aVal, bVal);
	OTChooser choose = OTChooser(send.getH());
	std::pair<EC_POINT *, std::pair<EC_POINT *, EC_POINT *>> vals;

	send.encryptValues(choose.getPoints().second, choose.getPoints().first);
	printf("oblivoius transfer was: %s\n", choose.decrypt(send.getKey(), send.getEncrypted().second, send.getEncrypted().first).c_str());
	send.encryptValues(choose.getPoints().first, choose.getPoints().second);
	printf("oblivoius transfer was: %s\n", choose.decrypt(send.getKey(), send.getEncrypted().second, send.getEncrypted().first).c_str());
	
	// TODO
	// cleanup code and TODO's
	// create a dkg sim with tecies (add code to tecies)
	// create a dkg sim with tecdsa (add code to tecdsa)
	// create the p2p net
	// create p2p bootstrap node code
	// create p2p logging

	cleanupOpenSSL();
	return 0;
}
