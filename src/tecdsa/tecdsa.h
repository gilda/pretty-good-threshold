#pragma once
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../dkg/dkg.h"
#include "../ssss/ssss.h"
#include "../mta/mta.h"
#include "../sha256/sha256.h"

class TECDSA{
	private:
		unsigned int id;
		unsigned int t;
		unsigned int n;
		BIGNUM *privK;
		BIGNUM *privGamma;
		BIGNUM *privDelta;
		BIGNUM *privSigma;
		EC_POINT *R;
		BIGNUM *delta;
		BIGNUM *r;
		BIGNUM *privS;
		BIGNUM *s;
		MtALeader *lead;
		MtAFollower *follow;

	public:
		DKG dkg;
		TECDSA(unsigned int id, unsigned int t, unsigned int n);
		static void doMtA(TECDSA *leader, TECDSA *follower);
		EC_POINT *getPrivGammaCommitment();
		
		// Simulation only
		MtAFollower *getCurrentFollower();
		MtALeader *getCurrentLeader();
		void setKGammaFollower();
		void setKGammaLeader();
		void setKPrivFollower();
		void setKPrivLeader();

		BIGNUM *getPrivDelta();
		void addPrivDelta(BIGNUM *delta);
		void addDelta(BIGNUM *delta);
		void addPrivSigma(BIGNUM *sigma);
		void addGammaCommitment(EC_POINT *gammaCommitment);
		void finalizeR();
		BIGNUM *getPrivS(unsigned char *message, unsigned int len);
		void addPrivS(BIGNUM *s);
		unsigned char *getSig();
};
