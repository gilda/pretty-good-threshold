#include "tecdsa.h"

TECDSA::TECDSA(unsigned int id, unsigned int t, unsigned int n){
	this->id = id;
	this->t = t;
	this->n = n;
	this->dkg = DKG(id, t, n);

	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();

	this->R = EC_POINT_new(group);
	if(this->R == NULL) handleErrors();

	this->delta = BN_new();
	if(this->delta == NULL) handleErrors();

	this->s = BN_new();
	if(this->s == NULL) handleErrors();

	this->privK = BN_new();
	int err = BN_rand_range(this->privK, SSSS().getP());
	if(err == 0) handleErrors();

	this->privGamma = BN_new();
	err = BN_rand_range(this->privGamma, SSSS().getP());
	if(err == 0) handleErrors();

	this->privDelta = BN_new();
	err = BN_mod_mul(this->privDelta, this->privK, this->privGamma, SSSS().getP(), ctx);
	if(err == 0) handleErrors();

	this->privSigma = BN_new();
	err = BN_mod_mul(this->privSigma, this->privK, this->dkg.getPrivateShare(), SSSS().getP(), ctx);
	if(err == 0) handleErrors();
}

void TECDSA::doMtA(TECDSA *leader, TECDSA *follower){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();
	
	for(int i = 0; i < 256; i++){
		follower->getCurrentFollower()->setCurrentH(leader->getCurrentLeader()->getCurrentH());
		leader->getCurrentLeader()->encryptCurrentValues(follower->getCurrentFollower()->getCurrentPoints().first, follower->getCurrentFollower()->getCurrentPoints().second);
		std::pair<std::pair<unsigned char **, int>, std::pair<unsigned char **, int>> enc = leader->getCurrentLeader()->getCurrentEncrypted();
		follower->getCurrentFollower()->decryptCurrent(leader->getCurrentLeader()->getCurrentKey(), enc.first, enc.second);
	}
}

EC_POINT *TECDSA::getPrivGammaCommitment(){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();

	EC_POINT *ret = EC_POINT_new(group);
	if(ret == NULL) handleErrors();

	int err = EC_POINT_mul(group, ret, this->privGamma, NULL, NULL, ctx);
	if(err == 0) handleErrors();

	return ret;
}

MtAFollower *TECDSA::getCurrentFollower(){
	return this->follow;
}

MtALeader *TECDSA::getCurrentLeader(){
	return this->lead;
}

void TECDSA::setKGammaFollower(){
	this->follow = new MtAFollower(this->privGamma);
}

void TECDSA::setKGammaLeader(){
	this->lead = new MtALeader(this->privK);
}

void TECDSA::setKPrivFollower(){
	this->follow = new MtAFollower(this->dkg.getPrivateShare());
}

void TECDSA::setKPrivLeader(){
	this->lead = new MtALeader(this->privK);
}

BIGNUM *TECDSA::getPrivDelta(){
	return this->privDelta;
}

void TECDSA::addPrivDelta(BIGNUM *delta){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	int err = BN_mod_add(this->privDelta, this->privDelta, delta, SSSS().getP(), ctx);
	if(err == 0) handleErrors();
}

void TECDSA::addDelta(BIGNUM *delta){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	int err = BN_mod_add(this->delta, this->delta, delta, SSSS().getP(), ctx);
	if(err == 0) handleErrors();
}

void TECDSA::addPrivSigma(BIGNUM *sigma){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	int err = BN_mod_add(this->privSigma, this->privSigma, sigma, SSSS().getP(), ctx);
	if(err == 0) handleErrors();
}

void TECDSA::addGammaCommitment(EC_POINT *gammaCommitment){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();
	
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();
	
	int err = EC_POINT_add(group, this->R, this->R, gammaCommitment, ctx);
	if(err == 0) handleErrors();
}

void TECDSA::finalizeR(){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();
	
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();

	this->delta = BN_mod_inverse(NULL, this->delta, SSSS().getP(), ctx);
	if(this->delta == NULL) handleErrors();

	int err = EC_POINT_mul(group, this->R, NULL, this->R, this->delta, ctx);
	if(err == 0) handleErrors();

	this->r = BN_new();

	err = EC_POINT_get_affine_coordinates(group, this->R, this->r, NULL, ctx);
	if(err == 0) handleErrors();
}

BIGNUM *TECDSA::getPrivS(unsigned char *message, unsigned int len){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	unsigned char *mHex = HASH::sha256(message, len);
	
	BIGNUM *m = BN_new(); 
	int err = BN_hex2bn(&m, encodeHex(mHex, 32).c_str());
	if(err == 0) handleErrors();

	this->privS = BN_new();
	BIGNUM *mk = BN_new();
	BIGNUM *rSigma = BN_new();

	err = BN_mod_mul(mk, m, this->privK, SSSS().getP(), ctx);
	if(err == 0) handleErrors();
	
	err = BN_mod_mul(rSigma, this->r, this->privSigma, SSSS().getP(), ctx);
	if(err == 0) handleErrors();
	
	err = BN_mod_add(this->privS, mk, rSigma, SSSS().getP(), ctx);
	if(err == 0) handleErrors();
	return this->privS;
}

void TECDSA::addPrivS(BIGNUM *s){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	int err = BN_mod_add(this->s, this->s, s, SSSS().getP(), ctx);
	if(err == 0) handleErrors();
}

unsigned char *TECDSA::getSig(){
	unsigned char *ret = new unsigned char[64*2];
	memcpy(ret, BN_bn2hex(this->r), 64);
	memcpy(ret + 64, BN_bn2hex(this->s), 64);
	
	return ret;
}
