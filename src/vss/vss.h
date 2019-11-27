#pragma once
#include <vector>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../ssss/ssss.h"

// TODO generate getters, setters and make all members private
// TODO comment
class VSS{
	public:
		unsigned int n;
		unsigned int t;

		VSS(unsigned int t, unsigned int n, const BIGNUM *secret);
		bool verifyShare(const Share share);
		std::vector<Share> getShares();
		BIGNUM *recoverSecret(std::vector<Share> shares);

		std::vector<EC_POINT *> getCommitments();
		void setCommitments(std::vector<EC_POINT *> commitments);
	
	private:
		std::vector<EC_POINT *> commitments;
		void generateCommitments();
		SSSS secretSharing;
};
