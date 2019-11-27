#include "vss.h"

// TODO cleanup openssl BN CTX & EC
VSS::VSS(unsigned int t, unsigned int n, const BIGNUM *secret){
	this->t = t;
	this->n = n;
	this->secretSharing = SSSS(t, n, secret);
	this->generateCommitments();
}

void VSS::generateCommitments(){
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	
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
	
	BN_CTX_end(ctx);
	BN_CTX_free(ctx);
	EC_GROUP_free(group);
}

// TODO make bool after fix
// TODO cleanup BN and EC, comment
bool VSS::verifyShare(const Share share){
	BN_CTX *ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL){
		printf("Not a valid name\n");
	}
	
	EC_POINT *target = EC_POINT_new(group);
	EC_POINT_mul(group, target, share.y, NULL, NULL, ctx);

	EC_POINT *commitPowered = EC_POINT_new(group);
	BIGNUM *iBN = BN_new();
	BIGNUM *xPowered = BN_new();
	EC_POINT *verify = EC_POINT_new(group);
	
	for(unsigned int i = 0; i < this->commitments.size(); i++){
		BN_dec2bn(&iBN, std::to_string(i).c_str());
		BN_mod_exp(xPowered, share.x, iBN, SSSS::p, ctx);
		EC_POINT_mul(group, commitPowered, NULL, this->commitments.at(i), xPowered, ctx);
		EC_POINT_add(group, verify, verify, commitPowered, ctx);
	}

	return EC_POINT_cmp(group, verify, target, ctx) == 0;
}

std::vector<Share> VSS::getShares(){
	return this->secretSharing.getShares();
}

BIGNUM *VSS::recoverSecret(std::vector<Share> shares){
	return this->secretSharing.recoverSecret(shares);
}

std::vector<EC_POINT *> VSS::getCommitments(){
	return this->commitments;
}

void VSS::setCommitments(std::vector<EC_POINT *> commitments){
	this->commitments = commitments;
}
