#include "vss.h"

VSS::VSS(unsigned int t, unsigned int n, const BIGNUM *secret){
	this->t = t;
	this->n = n;
	this->secretSharing = SSSS(t, n, secret);

	this->rand = BN_new();
	if(this->rand == NULL) handleErrors();
	BN_rand_range(rand, SSSS::getP());
	this->randomSharing = SSSS(t, n, rand);

	this->generateCommitments();
}

VSS::VSS(){
	
}

bool VSS::verifyShare(std::vector<EC_POINT *> commitments, const VSSShare share){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();
	
	EC_POINT *target = EC_POINT_new(group);
	if(target == NULL) handleErrors();

	// target = g^secretShare.y*h^randomShare.y
	target = PCommitment::commit(share.secret.y, share.random.y);

	EC_POINT *commitPowered = EC_POINT_new(group);
	if(commitPowered == NULL) handleErrors();

	BIGNUM *iBN = BN_new();
	if(iBN == NULL) handleErrors();

	BIGNUM *xPowered = BN_new();
	if(xPowered == NULL) handleErrors();

	EC_POINT *verify = EC_POINT_new(group);
	if(verify == NULL) handleErrors();
	
	for(unsigned int i = 0; i < commitments.size(); i++){
		if(BN_dec2bn(&iBN, std::to_string(i).c_str()) == 0) handleErrors();

		// xPowered = share.x^i
		if(BN_mod_exp(xPowered, share.secret.x, iBN, SSSS::getP(), ctx) == 0) handleErrors();

		// commitPowered = commitment[i]^xPowred
		if(EC_POINT_mul(group, commitPowered, NULL, commitments.at(i), xPowered, ctx) == 0) handleErrors();
		
		// verify = verify + commitPowered
		if(EC_POINT_add(group, verify, verify, commitPowered, ctx) == 0) handleErrors();
	}

	// ret = cmp(verify, target)
	int intRet = EC_POINT_cmp(group, verify, target, ctx); 
	if(intRet == -1){
		handleErrors();
	}

	// cleanup
	BN_CTX_free(ctx);
	EC_GROUP_free(group);
	EC_POINT_free(target);
	EC_POINT_free(commitPowered);
	BN_free(iBN);
	BN_free(xPowered);

	// return result
	return intRet == 0;
}

std::pair<BIGNUM *, BIGNUM *> VSS::recoverSecret(std::vector<VSSShare> shares){
	std::vector<Share> secret;
	std::vector<Share> random;

	for(unsigned int i = 0; i < shares.size(); i++){
		secret.push_back(shares.at(i).secret);
		random.push_back(shares.at(i).random);
	}

	return std::pair<BIGNUM *, BIGNUM *>(this->secretSharing.recoverSecret(secret), this->secretSharing.recoverSecret(random));
}

std::vector<VSSShare> VSS::getShares(){
	std::vector<VSSShare> ret;
	for(unsigned int i = 0; i < this->secretSharing.getShares().size(); i++){
		VSSShare iShare;
		iShare.secret = this->secretSharing.getShares().at(i);
		iShare.random = this->randomSharing.getShares().at(i);

		ret.push_back(iShare);
	}

	return ret;
}


std::vector<EC_POINT *> VSS::getCommitments(){
	return this->commitments;
}

EC_POINT *VSS::getMasterCommit(){
	return PCommitment::commit(this->secretSharing.recoverSecret(this->secretSharing.getShares()), this->rand);
}

unsigned int VSS::getN(){
	return this->n;
}

unsigned int VSS::getT(){
	return this->t;
}

void VSS::generateCommitments(){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();
	
	// TODO export group to static at util
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();

	// commit to the polynomial paramaters
	for(unsigned int i = 0; i < this->secretSharing.getPolynomial().size(); i++){	
		EC_POINT *commit = EC_POINT_new(group);
		if(commit == NULL) handleErrors();

		// commit = g^poly[i]*h^randPoly[i]
		commit = PCommitment::commit(this->secretSharing.getPolynomial().at(i), this->randomSharing.getPolynomial().at(i));
		if(commit == NULL) handleErrors();

		this->commitments.push_back(commit);
	}
	
	// cleunup
	BN_CTX_free(ctx);
	EC_GROUP_free(group);
}
