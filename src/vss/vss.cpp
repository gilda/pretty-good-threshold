#include "vss.h"

VSS::VSS(unsigned int t, unsigned int n, BIGNUM *secret){
	this->secretSharing = SSSS(t, n, secret);
}

std::vector<Share> VSS::generateShares(){
	return this->secretSharing.generateShares();
}

BIGNUM *VSS::recoverSecret(std::vector<Share> shares){
	return this->secretSharing.recoverSecret(shares);
}
