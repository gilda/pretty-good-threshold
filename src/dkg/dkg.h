#pragma once
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../vss/vss.h"
#include "../ssss/ssss.h"
#include "../util/util.h"

class DKG{
	private:
		unsigned int t;
		unsigned int n;
		VSS secret;

	public:
		DKG(unsigned int t, unsigned int n);
		std::vector<EC_POINT *> getCommitments();
		VSSShare getShare(unsigned int i);
		std::vector<VSSShare> getShares();
		static bool verifyShare(std::vector<EC_POINT *> commitments, VSSShare share);
		EC_POINT *getSecretCommitment();
		static EC_POINT *getPublicKey(std::vector<EC_POINT *> commitments);
};
