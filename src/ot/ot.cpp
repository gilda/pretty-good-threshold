#include "ot.h"

OTSender::OTSender(std::string a, std::string b){
	unsigned char *charX = HASH::sha256(randomPrivateBytes(32), 32);
	
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();

	BIGNUM *x = BN_bin2bn(charX, 32, NULL);
	if(x == NULL) handleErrors();

	EC_POINT *h = EC_POINT_new(group);
	if(h == NULL) handleErrors();

	int err = EC_POINT_set_compressed_coordinates(group, h, x, (int)(*randomPrivateBytes(0) % 2), ctx);
	while(err == 0){
		ERR_clear_error();
		charX = HASH::sha256(randomPrivateBytes(32), 32);
		x = BN_bin2bn(charX, 32, NULL);
		err = EC_POINT_set_compressed_coordinates(group, h, x, (int)(*randomPrivateBytes(0) % 2), ctx);
	}

	this->h = h;
	this->a = a;
	this->b = b;
	this->encA = new unsigned char *[3];
	this->encB = new unsigned char *[3];
}

OTSender::OTSender(){}

EC_POINT *OTSender::getH(){
	return this->h;
}

EC_KEY *OTSender::getKey(){
	return this->ecKey;
}

bool OTSender::verifyPoints(EC_POINT *p1, EC_POINT *p2){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();

	EC_POINT *target = EC_POINT_new(group);
	if(target == NULL) handleErrors();

	int err = EC_POINT_add(group, target, p1, p2, ctx);
	if(err == 0) handleErrors();

	int ret = EC_POINT_cmp(group, target, this->h, ctx);
	if(ret == -1) handleErrors();

	return ret == 0;
}

void OTSender::encryptValues(EC_POINT *p1, EC_POINT *p2){
	if(!verifyPoints(p1, p2)){
		printf("OTSender::encryptValues - bad points");
		return;
	}

	this->ecKey = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_generate_key(ecKey);

	EC_KEY *keyP1 = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_set_public_key(keyP1, p1);

	this->enc = ECIES(ecKey, keyP1);

	unsigned char *aCtext = new unsigned char[((this->a.length() / 16 + 1)*16)];
	this->encALen = enc.encrypt(a, "", aCtext);

	this->encA[0] = aCtext;
	this->encA[1] = enc.getIv();
	this->encA[2] = enc.getTag();

	EC_KEY *keyP2 = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_set_public_key(keyP2, p2);

	this->enc = ECIES(ecKey, keyP2);

	unsigned char *bCtext = new unsigned char[((this->b.length() / 16 + 1)*16)];
	this->encBLen = enc.encrypt(b, "", bCtext);

	this->encB[0] = bCtext;
	this->encB[1] = enc.getIv();
	this->encB[2] = enc.getTag();
}

std::pair<std::pair<unsigned char **, int>, std::pair<unsigned char **, int>> OTSender::getEncrypted(){
	return std::pair<std::pair<unsigned char **, int>, std::pair<unsigned char **, int>>
	(std::pair<unsigned char **, int>(this->encA, this->encALen), 
	 std::pair<unsigned char **, int>(this->encB, this->encBLen));
}

OTChooser::OTChooser(EC_POINT *h){	
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();

	this->choice = EC_POINT_new(group);
	if(this->choice == NULL) handleErrors();

	this->key = BN_new();
	BN_rand_range(this->key, SSSS().getP());

	int err = EC_POINT_mul(group, this->choice, this->key, NULL, NULL, ctx);
	if(err == 0) handleErrors();

	BIGNUM *choiceX = BN_new();
	if(choiceX == NULL) handleErrors();

	BIGNUM *choiceY = BN_new();
	if(choiceY == NULL) handleErrors();

	err = EC_POINT_get_affine_coordinates(group, this->choice, choiceX, choiceY, ctx);
	if(err == 0) handleErrors();

	EC_POINT *negKey = EC_POINT_new(group);
	if(negKey == NULL) handleErrors();

	err = EC_POINT_set_compressed_coordinates(group, negKey, choiceX, BN_is_odd(choiceY) == 0 ? 1 : 0, ctx);
	if(err == 0) handleErrors();

	this->p2 = EC_POINT_new(group);
	if(this->p2 == NULL) handleErrors();

	err = EC_POINT_add(group, this->p2, h, negKey, ctx);
	if(err == 0) handleErrors();
}

OTChooser::OTChooser(){}

std::pair<EC_POINT *, EC_POINT *> OTChooser::getPoints(){
	return std::pair<EC_POINT *, EC_POINT *>(this->choice, this->p2);
}

std::string OTChooser::decrypt(EC_KEY *key, std::pair<unsigned char **, int> a, std::pair<unsigned char **, int> b){
	EC_KEY *decKey = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_set_private_key(decKey, this->key);
	EC_KEY_set_public_key(decKey, this->choice);
	
	this->dec = ECIES(decKey, key);
	
	this->dec.setIv(a.first[1]);
	this->dec.setTag(a.first[2]);
	std::string ret = this->dec.decrypt(a.first[0], a.second, "");

	if(ret != "") return ret;

	this->dec.setIv(b.first[1]);
	this->dec.setTag(b.first[2]);
	ret = this->dec.decrypt(b.first[0], b.second, "");

	return ret;
}
