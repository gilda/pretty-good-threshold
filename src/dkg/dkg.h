#pragma once
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../vss/vss.h"
#include "../ssss/ssss.h"
#include "../util/util.h"

class DKG{
	private:
		unsigned int id;
		unsigned int t;
		unsigned int n;
		VSS secret;
		std::vector<EC_POINT *> *commitments;
		VSSShare *shares;
		EC_POINT **publicKeyCommitments;
		BIGNUM **privateKeyShares;

	public:
		DKG(unsigned int id, unsigned int t, unsigned int n);
		DKG();
		BIGNUM *getPrivateShare();
		void addPrivateShare(unsigned int n, BIGNUM *share);
		BIGNUM *getPrivateKey();
		std::vector<EC_POINT *> getCommitments();
		void addNodeCommitments(unsigned int n, std::vector<EC_POINT *> commitments);
		VSSShare getShare(unsigned int i);
		std::vector<VSSShare> getShares();
		void addNodeShare(unsigned int n, VSSShare share);
		static bool verifyShare(std::vector<EC_POINT *> commitments, VSSShare share);
		bool verifyShare(unsigned int id);
		EC_POINT *getPublicKeyCommitment();
		void addPublicKeyCommitment(unsigned int n, EC_POINT *commitment);
		static EC_POINT *getPublicKey(std::vector<EC_POINT *> commitments);
		EC_POINT *getPublicKey();
};
