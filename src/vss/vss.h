#pragma once
#include <vector>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../ssss/ssss.h"
#include "../util/util.h"

class VSS{
	public:
		// init params and create commitments
		VSS(unsigned int t, unsigned int n, const BIGNUM *secret);
		
		// verify a share using feldman VSS
		bool verifyShare(const Share share);
		
		// return the recovered secret while verifieng each share
		BIGNUM *recoverSecret(std::vector<Share> shares);
	
		// getters
		std::vector<Share> getShares();
		std::vector<EC_POINT *> getCommitments();
		unsigned int getN();
		unsigned int getT();

	private:
		unsigned int n;
		unsigned int t;
		std::vector<EC_POINT *> commitments;
		SSSS secretSharing;

		// generate the g^poly[i] commitments
		void generateCommitments();
};
