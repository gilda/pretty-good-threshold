#pragma once
#include <vector>
#include <string>
#include <openssl/bn.h>

class Share{
	public:
		BIGNUM *x;
		BIGNUM *y;
		bool isEmpty();
};

class SSSS{
	public:
		static BIGNUM* p;
		unsigned int n;
		unsigned int t;
		
		// init params and create poly
		// NOTE: t is enough to recover, t-1 is not
		SSSS(unsigned int t, unsigned int n, BIGNUM *secret);

		// NOTE: all arithmetic is done mod large prime p
		// generate n random points on a t degree curve, secret is f(0)
		std::vector<Share> generateShares();
		
		// interpolate >t points to find f(0)
		BIGNUM *recoverSecret(std::vector<Share> shares);

		~SSSS();
	private:
		std::vector<BIGNUM *> poly;
		BIGNUM *evalPoly(BIGNUM *x);
		bool validShares(std::vector<Share> shares, unsigned int t);
		BIGNUM *lagrangeBasePoly(std::vector<Share> shares, BIGNUM *x, int j);
		BIGNUM *lagrangeInterpolation(std::vector<Share> shares, BIGNUM *x);
};