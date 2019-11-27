#include "vss.h"

VSS::VSS(unsigned int t, unsigned int n, const BIGNUM *secret){
	this->t = t;
	this->n = n;
	this->secretSharing = SSSS(t, n, secret);
	this->generateCommitments();
}

bool VSS::verifyShare(const Share share){
	BN_CTX *ctx = BN_CTX_new();
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL){
		printf("Not a valid name\n");
	}
	
	EC_POINT *target = EC_POINT_new(group);

	// target = g^share.y
	EC_POINT_mul(group, target, share.y, NULL, NULL, ctx);

	EC_POINT *commitPowered = EC_POINT_new(group);
	BIGNUM *iBN = BN_new();
	BIGNUM *xPowered = BN_new();
	EC_POINT *verify = EC_POINT_new(group);
	
	for(unsigned int i = 0; i < this->commitments.size(); i++){
		BN_dec2bn(&iBN, std::to_string(i).c_str());

		// xPowered = share.x^i
		BN_mod_exp(xPowered, share.x, iBN, SSSS::getP(), ctx);
		
		// commitPowered = commitment[i]^xPowred
		EC_POINT_mul(group, commitPowered, NULL, this->commitments.at(i), xPowered, ctx);
		
		// verify = verify + commitPowered
		EC_POINT_add(group, verify, verify, commitPowered, ctx);
	}

	// ret = cmp(verify, target)
	bool ret = EC_POINT_cmp(group, verify, target, ctx) == 0; 
	
	// cleanup
	BN_CTX_free(ctx);
	EC_GROUP_free(group);
	EC_POINT_free(target);
	EC_POINT_free(commitPowered);
	BN_free(iBN);
	BN_free(xPowered);

	// return result
	return ret;
}

// TODO verify each share
BIGNUM *VSS::recoverSecret(std::vector<Share> shares){
	return this->secretSharing.recoverSecret(shares);
}

std::vector<Share> VSS::getShares(){
	return this->secretSharing.getShares();
}


std::vector<EC_POINT *> VSS::getCommitments(){
	return this->commitments;
}

unsigned int VSS::getN(){
	return this->n;
}

unsigned int VSS::getT(){
	return this->t;
}

void VSS::generateCommitments(){
	BN_CTX *ctx = BN_CTX_new();
	
	// TODO export group to static at util
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL){
		printf("Not a valid name\n");
	}

	// commit to the polynomial paramaters
	for(unsigned int i = 0; i < this->secretSharing.getPolynomial().size(); i++){	
		EC_POINT *commit = EC_POINT_new(group);

		// commit = g^poly[i]
		EC_POINT_mul(group, commit, this->secretSharing.getPolynomial().at(i), NULL, NULL, ctx);

		this->commitments.push_back(commit);
	}
	
	// cleunup
	BN_CTX_free(ctx);
	EC_GROUP_free(group);
}
