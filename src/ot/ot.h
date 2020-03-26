#pragma once
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../ssss/ssss.h"
#include "../sha256/sha256.h"
#include "../ecies/ecies.h"
#include "../util/util.h"

class OTSender{
	private:
		std::string a;
		std::string b;
		int encALen;
		int encBLen;
		unsigned char **encA;
		unsigned char **encB;
		BIGNUM *key;
		EC_POINT *h;
		EC_KEY *ecKey;
		ECIES enc;

		bool verifyPoints(EC_POINT *p1, EC_POINT *p2);

	public:
		OTSender(std::string a, std::string b);
		EC_POINT *getH();
		EC_KEY *getKey();
		void encryptValues(EC_POINT *p1, EC_POINT *p2);
		std::pair<std::pair<unsigned char **, int>, std::pair<unsigned char **, int>> getEncrypted();
};

class OTChooser{
	private:
		EC_POINT *choice;
		EC_POINT *p2;
		BIGNUM *key;
		ECIES dec;

	public:
		OTChooser(EC_POINT *h);
		std::pair<EC_POINT *, EC_POINT *>getPoints();
		std::string decrypt(EC_KEY *key, std::pair<unsigned char **, int>, std::pair<unsigned char **, int>);
};
