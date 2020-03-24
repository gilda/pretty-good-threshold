#pragma once
#include <vector>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../ssss/ssss.h"
#include "../pcommit/pcommit.h"
#include "../util/util.h"

class VSSShare{
	public:
		Share secret;
		Share random;
};

class VSS{
	public:
		// init params and create commitments
		VSS(unsigned int t, unsigned int n, const BIGNUM *secret);
		VSS();

		// verify a share using feldman VSS
		static bool verifyShare(std::vector<EC_POINT *> commitments, const VSSShare share);
		
		// return the recovered secret while verifieng each share
		std::pair<BIGNUM *, BIGNUM *> recoverSecret(std::vector<VSSShare> shares);
	
		// getters
		std::vector<VSSShare> getShares();
		std::vector<EC_POINT *> getCommitments();
		EC_POINT *getMasterCommit();
		unsigned int getN();
		unsigned int getT();

	private:
		unsigned int n;
		unsigned int t;
		BIGNUM *rand;
		std::vector<EC_POINT *> commitments;
		SSSS secretSharing;
		SSSS randomSharing;

		// generate the g^poly[i] commitments
		void generateCommitments();
};
