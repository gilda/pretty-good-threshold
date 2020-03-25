#include "dkg.h"

DKG::DKG(unsigned int id, unsigned int t, unsigned int n){
	this->id = id;
	this->t = t;
	this->n = n;

	this->commitments = new std::vector<EC_POINT *>[this->n];
	this->publicKeyCommitments = new EC_POINT *[this->n];
	this->privateKeyShares = new BIGNUM *[this->n];
	this->shares = new VSSShare[this->n];

	BIGNUM *bn = BN_new();
	if(bn == NULL) handleErrors();
	int err = BN_rand_range(bn, SSSS::getP());
	if(err == 0) handleErrors();

	this->secret = VSS(t, n, bn);

	this->addNodeShare(this->id, this->getShare(this->id));
	this->addNodeCommitments(this->id, this->getCommitments());
	this->addPublicKeyCommitment(this->id, this->getPublicKeyCommitment());
	this->addPrivateShare(this->id, this->getPrivateShare());
}

BIGNUM *DKG::getPrivateShare(){
	return this->secret.recoverSecret(this->secret.getShares()).first;
}

void DKG::addPrivateShare(unsigned int n, BIGNUM *share){
	this->privateKeyShares[n] = share;
}

BIGNUM *DKG::getPrivateKey(){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	BIGNUM *privateKey = BN_new();
	if(privateKey == NULL) handleErrors();

	BIGNUM *temp = BN_new();
	if(temp == NULL) handleErrors();

	int err;
	for(unsigned int i = 0; i < this->n; i++){
		BN_copy(temp, privateKey);
		err = BN_mod_add(privateKey, temp, this->privateKeyShares[i], SSSS::getP(), ctx);
		if(err == 0) handleErrors();
	}

	return privateKey;
}

std::vector<EC_POINT *> DKG::getCommitments(){
	return this->secret.getCommitments();
}

void DKG::addNodeCommitments(unsigned int n, std::vector<EC_POINT *> commitments){
	this->commitments[n] = commitments;
}

VSSShare DKG::getShare(unsigned int i){
	if(i > this->n) return VSSShare();
	return this->secret.getShares().at(i);
}

std::vector<VSSShare> DKG::getShares(){
	return this->secret.getShares();
}

void DKG::addNodeShare(unsigned int n, VSSShare share){
	this->shares[n] = share;
}

// TODO make sure all commitments are full and reach n
bool DKG::verifyShare(std::vector<EC_POINT *> commitments, VSSShare share){
	return VSS::verifyShare(commitments, share);
}

bool DKG::verifyShare(unsigned int id){
	return VSS::verifyShare(this->commitments[id], this->shares[id]);
}

EC_POINT *DKG::getPublicKeyCommitment(){
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

void DKG::addPublicKeyCommitment(unsigned int n, EC_POINT *commitment){
	this->publicKeyCommitments[n] = commitment;
}

EC_POINT *DKG::getPublicKey(std::vector<EC_POINT *> commitments){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();
	
	EC_POINT *publicKey = EC_POINT_new(group);
	if(publicKey == NULL) handleErrors();
	
	int err;
	for(unsigned int i = 0; i < commitments.size(); i++){
		err = EC_POINT_add(group, publicKey, publicKey, commitments.at(i), ctx);
		if(err == 0) handleErrors();
	}

	return publicKey;
}

// TODO make sure all commitments are full and reach n
EC_POINT *DKG::getPublicKey(){
	std::vector<EC_POINT *> commitVector;
	for(unsigned int i = 0; i < this->n; i++){
		commitVector.push_back(this->publicKeyCommitments[i]);
	}

	return DKG::getPublicKey(commitVector);
}
