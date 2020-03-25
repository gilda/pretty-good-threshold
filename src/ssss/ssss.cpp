#include "ssss.h"

bool Share::isEmpty(){
	return this->x == NULL || this->y == NULL;
}

SSSS::SSSS(unsigned int t, unsigned int n, const BIGNUM *secret){
	this->t = t;
	this->n = n;

	if(t > n){
		throw std::exception();
		return;
	}

	// TODO remove def of prime to field of ecc export to static at util
	if(BN_hex2bn(&this->p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") == 0) handleErrors();

	this->generatePoly(secret);

	this->generateShares();
}

SSSS::SSSS(){
	this->t = 0;
	this->n = 0;
	this->poly = std::vector<BIGNUM *>();
	if(BN_hex2bn(&this->p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") == 0) handleErrors();
}

BIGNUM *SSSS::p;

// lagrange interpolate over t shares
BIGNUM *SSSS::recoverSecret(std::vector<Share> shares){
	// assert different and all != 0 x of t shares
	if(!validShares(shares, this->t)){
		throw std::exception();
		return NULL;
	}

	return lagrangeInterpolation(shares, BN_new());
}

std::vector<BIGNUM *> SSSS::getPolynomial(){
	std::vector<BIGNUM *> ret = this->poly;
	return ret;
}

std::vector<Share> SSSS::getShares(){
	return this->shares;
}

BIGNUM *SSSS::getP(){
	return p;
} 

unsigned int SSSS::getN(){
	return this->n;
}

unsigned int SSSS::getT(){
	return this->t;
}

// free all BIGNUMs
SSSS::~SSSS(){
	for(auto it = this->poly.begin(); it != this->poly.end(); it++){
		// TODO figure out double free or corruption
		//BN_free(*it);
	}
};

void SSSS::generatePoly(const BIGNUM *secret){
	// generate polynomial
	for(unsigned int i = 0; i < this->t; i++){
		if(i == 0){
			BIGNUM *a = BN_dup(secret);
			if(a == NULL) handleErrors();
			
			this->poly.push_back(a);
		}else{
			BIGNUM *rand = BN_new();
			if(rand == NULL) handleErrors();
			
			if(BN_rand_range(rand, SSSS::p) == 0) {}
			this->poly.push_back(rand);
		}
	}
}

// returns n shares on polynomial, not at x = 0
void SSSS::generateShares(){
	std::vector<Share> ret;
	
	// eval n points on curve with x = 1 ... n + 1
	for(unsigned int i = 1; i < this->n + 1; i++){
		Share p;
		p.x = BN_new();
		if(p.x == NULL) {}
		
		if(BN_dec2bn(&p.x, std::to_string(i).c_str()) == 0) {}
		
		p.y = this->evalPoly(p.x);
		this->shares.push_back(p);
	}
}

// evaluate the polynomial at x
BIGNUM *SSSS::evalPoly(const BIGNUM *x){
	BIGNUM *ret = BN_new();
	if(ret == NULL) {}
	
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) {}
	
	for(unsigned int i = 0; i < this->t; i++){
		// xEval = x^i % p
		BIGNUM *iBN = BN_new();
		if(iBN == NULL) {}

		BIGNUM *xEval = BN_new();
		if(xEval == NULL) {}
		
		if(BN_dec2bn(&iBN, std::to_string(i).c_str()) == 0) {}
		if(BN_mod_exp(xEval, x, iBN, this->p, ctx) == 0) {}

		// paramBN = poly[i] * xEval % p
		BIGNUM *paramBN = BN_new();
		if(paramBN == NULL) {}
		BN_mod_mul(paramBN, this->poly.at(i), xEval, this->p, ctx);
		
		// ret = final + paramBN % p
		BIGNUM *final = BN_dup(ret);
		if(final == NULL) {}
		
		if(BN_mod_add(ret, final, paramBN, this->p, ctx) == 0) {}
	
		// free intermediate values
		BN_free(xEval);
		BN_free(paramBN);
		BN_free(final);
	}

	// free context
	BN_CTX_free(ctx);
	return ret;
}

// assert different and all != 0 x of t shares
bool SSSS::validShares(std::vector<Share> shares, unsigned int t){
	if(shares.size() < t){
		throw std::exception();
		return false;
	}else{
		for(auto it = shares.begin(); it != shares.end(); it++){
			if(it->isEmpty()){
				throw std::exception();
				return false;
			}
			if(BN_is_zero(it->x)){
				throw std::exception();
				return false;
			}else{
				for(auto jt = shares.begin(); jt != shares.end(); jt++){
					if(jt->isEmpty()){
						throw std::exception();
						return false;
					}
					if(it == jt){
						continue;
					}
					if(BN_cmp(it->x, jt->x) == 0){
						throw std::exception();
						return false;
					}
				}
			}
		}
		return true;
	}
};

// return the base polynomial of the lagrange interpolation at x
BIGNUM *SSSS::lagrangeBasePoly(std::vector<Share> shares, const BIGNUM *x, int j){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) {}
	
	// ret = 1
	BIGNUM *ret = BN_new();
	if(ret == NULL) {}
	
	if(BN_copy(ret, BN_value_one()) == NULL) {}
	
	BIGNUM *jBN = BN_new();
	if(jBN == NULL) {}
	
	if(BN_dec2bn(&jBN, std::to_string(j).c_str()) == 0) {}
	
	for(unsigned int m = 0; m < this->t; m++){
		// m == j continue;
		BIGNUM *mBN = BN_new();
		if(mBN == NULL) {}
		
		if(BN_dec2bn(&mBN, std::to_string(m).c_str()) == 0) {}
		if(BN_cmp(jBN, mBN) == 0){
			continue;
		}

		// nomi = x - xm % p
		BIGNUM *nomi = BN_new();
		if(nomi == NULL) {}

		if(BN_mod_sub(nomi, x, shares.at(m).x, this->p, ctx) == 0) {}

		// denomi = xj -xm % p
		BIGNUM *denomi = BN_new();
		if(denomi == NULL) {}

		if(BN_mod_sub(denomi, shares.at(j).x, shares.at(m).x, this->p, ctx) == 0) {}

		// inverse = denomi ^ -1 % p
		BIGNUM *inverse = BN_new();
		if(inverse == NULL) {}

		if(BN_mod_inverse(inverse, denomi, this->p, ctx) == 0) {}

		// frac = nomi * inverse % p
		BIGNUM *frac = BN_new();
		if(frac == NULL) {}

		if(BN_mod_mul(frac, nomi, inverse, this->p, ctx) == 0) {}

		// ret = temp * frac
		BIGNUM *temp = BN_dup(ret);
		if(temp == NULL) {}

		if(BN_mod_mul(ret, temp, frac, this->p, ctx) == 0) {}
	}

	return ret;
}

// return the evaluation interpolated polynomial
BIGNUM *SSSS::lagrangeInterpolation(std::vector<Share> shares, const BIGNUM *x){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) {}

	BIGNUM *ret = BN_new();
	if(ret == NULL) {}

	for(unsigned int j = 0; j < this->t; j++){
		// mult = yj*lj(x)
		BIGNUM *mult = BN_new();
		if(mult == NULL) {}

		BIGNUM *ljx = lagrangeBasePoly(shares, x, j);
		if(BN_mod_mul(mult, shares.at(j).y, ljx, this->p, ctx) == 0) {}

		// ret = temp + mult
		BIGNUM *temp = BN_dup(ret);
		if(temp == NULL) {}

		if(BN_mod_add(ret, temp, mult, this->p, ctx) == 0) {}

		BN_free(mult);
		BN_free(ljx);
		BN_free(temp);
	}

	BN_CTX_free(ctx);
	return ret;
}

SSSSDealer::SSSSDealer(unsigned int t, unsigned int n, const BIGNUM *secret){
	this->ssss = new SSSS(t, n, secret);
}

std::vector<Share> SSSSDealer::getShares(){
	return this->ssss->getShares();
}

SSSSReconstructor::SSSSReconstructor(unsigned int t, unsigned int n){
	this->ssss = new SSSS(t, n, BN_new());
}

void SSSSReconstructor::addShare(Share share){
	this->shares.push_back(share);
}

void SSSSReconstructor::setShares(std::vector<Share> shares){
	this->shares = shares;
}

BIGNUM *SSSSReconstructor::recoverSecret(){
	return this->ssss->recoverSecret(this->shares);
}
