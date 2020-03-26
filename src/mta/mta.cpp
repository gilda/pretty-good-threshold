#include "mta.h"

MtALeader::MtALeader(BIGNUM *b){
	this->secret = b;
	this->index = 0;
	this->accumulated = BN_new();
}

EC_POINT *MtALeader::getCurrentH(){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();

	BIGNUM *currentS = BN_new();
	int err = BN_rand_range(currentS, SSSS().getP());
	if(err == 0) handleErrors();

	BIGNUM *two = BN_new();
	BN_set_word(two, 2);

	BIGNUM *i = BN_new();
	BN_set_word(i, this->index);

	BIGNUM *t = BN_new();
	BN_mod_exp(t, two, i, SSSS().getP(), ctx);
	BN_mod_mul(t, t, this->secret, SSSS().getP(), ctx);
	BN_mod_add(t, t, currentS, SSSS().getP(), ctx);

	this->sender = OTSender(std::string(BN_bn2hex(currentS)), std::string(BN_bn2hex(t)));

	BN_mod_sub(this->accumulated, this->accumulated, currentS, SSSS().getP(), ctx);

	return this->sender.getH();
}

void MtALeader::encryptCurrentValues(EC_POINT *p1, EC_POINT *p2){
	this->sender.encryptValues(p1, p2);
}

EC_KEY *MtALeader::getCurrentKey(){
	return this->sender.getKey();
}

BIGNUM *MtALeader::finalize(){
	if(index < 255){
		return NULL;
	}

	return this->accumulated;
}

std::pair<std::pair<unsigned char **, int>, std::pair<unsigned char **, int>> MtALeader::getCurrentEncrypted(){
	this->index++;
	return this->sender.getEncrypted();
}

MtAFollower::MtAFollower(BIGNUM *a){
	this->secret = a;
	this->index = 0;
	this->accumulated = BN_new();
}

void MtAFollower::setCurrentH(EC_POINT *h){
	this->chooser = OTChooser(h);
}

std::pair<EC_POINT *, EC_POINT *> MtAFollower::getCurrentPoints(){
	std::pair<EC_POINT *, EC_POINT *> ret;
	EC_POINT *first = this->chooser.getPoints().first;
	EC_POINT *second = this->chooser.getPoints().second;

	if(BN_is_bit_set(this->secret, this->index)) return std::pair<EC_POINT *, EC_POINT *>(second, first);

	return this->chooser.getPoints();
}

void MtAFollower::decryptCurrent(EC_KEY *key, std::pair<unsigned char **, int> first, std::pair<unsigned char **, int> second){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();
	
	BIGNUM *add = BN_new();
	BN_hex2bn(&add, this->chooser.decrypt(key, first, second).c_str());
	
	BN_mod_add(this->accumulated, this->accumulated, add, SSSS().getP(), ctx);

	this->index++;
}

BIGNUM *MtAFollower::finalize(){
	if(index < 255){
		return NULL;
	}

	return this->accumulated;
}
