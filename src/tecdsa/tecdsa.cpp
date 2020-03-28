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

void TECDSA::doMtA(MtALeader *lead, MtAFollower *follow){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();
	
	for(int i = 0; i < 256; i++){
		follow->setCurrentH(lead->getCurrentH());
		lead->encryptCurrentValues(follow->getCurrentPoints().first, follow->getCurrentPoints().second);
		std::pair<std::pair<unsigned char **, int>, std::pair<unsigned char **, int>> enc = lead->getCurrentEncrypted();
		follow->decryptCurrent(lead->getCurrentKey(), enc.first, enc.second);
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

MtAFollower *TECDSA::getKGammaFollower(){
	return new MtAFollower(this->privGamma);
}

void TECDSA::leadKGammaMtA(unsigned int id, MtAFollower *ot){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();
	
	MtALeader *lead = new MtALeader(this->privK);
	this->doMtA(lead, ot);

	int err = BN_mod_add(this->privDelta, this->privDelta, lead->finalize(), SSSS().getP(), ctx);
	if(err == 0) handleErrors();
}

MtALeader *TECDSA::getKGammaLeader(){
	return new MtALeader(this->privK);
}

void TECDSA::followKGammaMtA(unsigned int id, MtALeader *ot){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();
	
	MtAFollower *follower = new MtAFollower(this->privGamma);
	this->doMtA(ot, follower);

	int err = BN_mod_add(this->privDelta, this->privDelta, follower->finalize(), SSSS().getP(), ctx);
	if(err == 0) handleErrors();
}

MtAFollower *TECDSA::getKPrivFollower(){
	return new MtAFollower(this->dkg.getPrivateShare());
}

void TECDSA::leadKPrivMtA(unsigned int id, MtAFollower *ot){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();
	
	MtALeader *lead = new MtALeader(this->privK);
	this->doMtA(lead, ot);

	int err = BN_mod_add(this->privDelta, this->privDelta, lead->finalize(), SSSS().getP(), ctx);
	if(err == 0) handleErrors();
}

MtALeader *TECDSA::getKPrivLeader(){
	return new MtALeader(this->privK);
}

void TECDSA::followKPrivMtA(unsigned int id, MtALeader *ot){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();
	
	MtAFollower *follower = new MtAFollower(this->privK);
	this->doMtA(ot, follower);

	int err = BN_mod_add(this->privDelta, this->privDelta, follower->finalize(), SSSS().getP(), ctx);
	if(err == 0) handleErrors();
}

BIGNUM *TECDSA::getDelta(){
	return this->privDelta;
}

void TECDSA::addDelta(BIGNUM *delta){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	int err = BN_mod_add(this->delta, this->delta, delta, SSSS().getP(), ctx);
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

std::pair<BIGNUM *, BIGNUM *> TECDSA::getSig(){
	return std::pair<BIGNUM *, BIGNUM *>(this->r, this->s);
}
