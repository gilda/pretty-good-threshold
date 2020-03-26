#pragma once
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../util/util.h"
#include "../ot/ot.h"

class MtALeader{
	private:
		unsigned int index;
		BIGNUM *secret;
		BIGNUM *accumulated;
		OTSender sender;

	public:
		MtALeader(BIGNUM *b);
		EC_POINT *getCurrentH();
		void encryptCurrentValues(EC_POINT *p1, EC_POINT *p2);
		EC_KEY *getCurrentKey();
		std::pair<std::pair<unsigned char **, int>, std::pair<unsigned char **, int>> getCurrentEncrypted();
		BIGNUM *finalize();
};

class MtAFollower{
	private:
		unsigned int index;
		BIGNUM *secret;
		BIGNUM *accumulated;
		OTChooser chooser;

	public:
		MtAFollower(BIGNUM *a);
		void setCurrentH(EC_POINT *h);
		std::pair<EC_POINT *, EC_POINT *> getCurrentPoints();
		void decryptCurrent(EC_KEY *key, std::pair<unsigned char **, int>, std::pair<unsigned char **, int>);
		BIGNUM *finalize();
};
