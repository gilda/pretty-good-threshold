#include "dkg.h"

DKG::DKG(unsigned int t, unsigned int n){
	this->t = t;
	this->n = n;

	BIGNUM *bn = BN_new();
	if(bn == NULL) handleErrors();
	BN_rand_range(bn, SSSS::getP());

	this->secret = VSS(t, n, bn);
}

std::vector<EC_POINT *> DKG::getCommitments(){
	return this->secret.getCommitments();
}

VSSShare DKG::getShare(unsigned int i){
	if(i > this->n) return VSSShare();
	return this->secret.getShares().at(i);
}

std::vector<VSSShare> DKG::getShares(){
	return this->secret.getShares();
}

bool DKG::verifyShare(std::vector<EC_POINT *> commitments, VSSShare share){
	return VSS::verifyShare(commitments, share);
}

EC_POINT *DKG::getSecretCommitment(){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();
	
	EC_POINT *secretCommitment = EC_POINT_new(group);
	if(secretCommitment == NULL) handleErrors();

	int err = EC_POINT_mul(group, secretCommitment, this->secret.recoverSecret(this->secret.getShares()).first, NULL, NULL, ctx);
	if(err == 0) handleErrors();

	return secretCommitment;
}

EC_POINT *DKG::getPublicKey(std::vector<EC_POINT *> commitments){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();
	
	EC_POINT *publicKey = EC_POINT_new(group);
	if(publicKey == NULL) handleErrors();

	BIGNUM *one = BN_new();
	BN_one(one);
	if(one == NULL) handleErrors();

	int err;
	for(unsigned int i = 0; i < commitments.size(); i++){
		err = EC_POINT_mul(group, publicKey, NULL, commitments.at(i), one, ctx);
		if(err == 0) handleErrors();
	}

	return publicKey;
}
