#pragma once
#include <vector>
#include <string>
#include <openssl/bn.h>
#include "../util/util.h"

class Share{
	public:
		BIGNUM *x;
		BIGNUM *y;
		bool isEmpty();
};

class SSSS{
	public:
		// init params and create poly
		// NOTE: t is enough to recover, t-1 is not
		SSSS(unsigned int t, unsigned int n, const BIGNUM *secret);
		SSSS();

		// interpolate >t points to find f(0)
		BIGNUM *recoverSecret(std::vector<Share> shares);

		// getters
		std::vector<BIGNUM *> getPolynomial();
		std::vector<Share> getShares();
		static BIGNUM *getP();
		unsigned int getN();
		unsigned int getT();

		// TODO destructor
		~SSSS();
	private:
		static BIGNUM* p;
		unsigned int n;
		unsigned int t;
		std::vector<BIGNUM *> poly;
		std::vector<Share> shares;
		
		// generate a random poly of degree t
		void generatePoly(const BIGNUM *secret);
		
		// generate n random points on a t degree curve, secret is f(0)
		void generateShares();
		
		// evaluate the poly at x = x 
		BIGNUM *evalPoly(const BIGNUM *x);

		// check that the shares vector is valid
		bool validShares(std::vector<Share> shares, unsigned int t);

		// generate and evaluate the lagrange base poly
		BIGNUM *lagrangeBasePoly(std::vector<Share> shares, const BIGNUM *x, int j);
		
		// interpolate the polynomial at x with some shares
		BIGNUM *lagrangeInterpolation(std::vector<Share> shares, const BIGNUM *x);
};