#pragma once
#include <vector>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../ssss/ssss.h"

// TODO generate getters, setters and make all members private
// TODO comment
class VSS{
	public:
		unsigned int n;
		unsigned int t;
		
		VSS(unsigned int t, unsigned int n, BIGNUM *secret);
		std::vector<EC_POINT> generateCommitments();
		bool verifyShare(Share share);
		std::vector<Share> generateShares();
		BIGNUM *recoverSecret(std::vector<Share> shares);
	
	private:
		SSSS secretSharing = SSSS(this->t, this->n, NULL);
};
