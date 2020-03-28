#pragma once
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
		BIGNUM *delta;
		EC_POINT *R;
		BIGNUM *inverseDelta;
		BIGNUM *r;
		BIGNUM *privS;
		BIGNUM *s;
		void doMtA(MtALeader *lead, MtAFollower *follow);

	public:
		DKG dkg;
		TECDSA(unsigned int id, unsigned int t, unsigned int n);
		EC_POINT *getPrivGammaCommitment();
		
		// Simulation only
		MtAFollower *getKGammaFollower();
		void leadKGammaMtA(unsigned int id, MtAFollower *ot);
		MtALeader *getKGammaLeader();
		void followKGammaMtA(unsigned int id, MtALeader *ot);
		MtAFollower *getKPrivFollower();
		void leadKPrivMtA(unsigned int id, MtAFollower *ot);
		MtALeader *getKPrivLeader();
		void followKPrivMtA(unsigned int id, MtALeader *ot);
		
		BIGNUM *getDelta();
		void addDelta(BIGNUM *delta);
		void addGammaCommitment(EC_POINT *gammaCommitment);
		void finalizeR();
		BIGNUM *getPrivS(unsigned char *message, unsigned int len);
		void addPrivS(BIGNUM *s);
		std::pair<BIGNUM *, BIGNUM *> getSig();
};
