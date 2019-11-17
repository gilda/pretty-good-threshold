#include "ssss.h"

bool Share::isEmpty(){
	return this->x == NULL || this->y == NULL;
}

BIGNUM *SSSS::p;

// TODO check errors BN_new == NULL
SSSS::SSSS(unsigned int t, unsigned int n, BIGNUM *secret){
	this->t = t;
	this->n = n;

	if(t > n){
		// TODO throw error
		return;
	}

	// TODO remove def of prime to field of ecc
	int err = BN_hex2bn(&this->p, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	if(err == 0){
		BN_free(this->p);
		// TODO throw error
	}
	
	// generate polynomial
	for(unsigned int i = 0; i < this->t; i++){
		if(i == 0){
			this->poly.push_back(secret);
		}else{
			BIGNUM *rand = BN_new();
			int err = BN_rand_range(rand, SSSS::p);
			if(err == 0){
				BN_free(rand);
				// TODO throw error
			}
			this->poly.push_back(rand);
		}
	}
}

// free all BIGNUMs
SSSS::~SSSS(){
	for(auto it = this->poly.begin(); it != this->poly.end(); it++){
		BN_free(*it);
	}
};

// returns n shares on polynomial, not at x = 0
std::vector<Share> SSSS::generateShares(){
	std::vector<Share> ret;
	
	// eval n points on curve with x = 1 ... n + 1
	for(unsigned int i = 1; i < this->n + 1; i++){
		Share p;
		p.x = BN_new();
		BN_dec2bn(&p.x, std::to_string(i).c_str());
		p.y = this->evalPoly(p.x);
		ret.push_back(p);
	}

	return ret;
}

// evaluate the polynomial at x
// TODO error check on BN ops
BIGNUM *SSSS::evalPoly(BIGNUM *x){
	BIGNUM *ret = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	
	for(unsigned int i = 0; i < this->t; i++){
		// xEval = x^i % p
		BIGNUM *iBN = BN_new();
		BIGNUM *xEval = BN_new();
		BN_dec2bn(&iBN, std::to_string(i).c_str());
		BN_mod_exp(xEval, x, iBN, this->p, ctx);

		// paramBN = poly[i] * xEval % p
		BIGNUM *paramBN = BN_new();
		BN_mod_mul(paramBN, this->poly.at(i), xEval, this->p, ctx);
		
		// ret = final + paramBN % p
		BIGNUM *final = BN_dup(ret);
		BN_mod_add(ret, final, paramBN, this->p, ctx);
	
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
		// TODO throw error
		return false;
	}else{
		for(auto it = shares.begin(); it != shares.end(); it++){
			if(it->isEmpty()){
				// TODO throw error
				return false;
			}
			if(BN_is_zero(it->x)){
				// TODO throw error
				return false;
			}else{
				for(auto jt = shares.begin(); jt != shares.end(); jt++){
					if(jt->isEmpty()){
						// TODO throw error
						return false;
					}
					if(it == jt){
						continue;
					}
					if(BN_cmp(it->x, jt->x) == 0){
						// TODO throw error
						return false;
					}
				}
			}
		}
		return true;
	}
};

// return the base polynomial of the lagrange interpolation at x
BIGNUM *SSSS::lagrangeBasePoly(std::vector<Share> shares, BIGNUM *x, int j){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *ret = BN_new();
	BN_copy(ret, BN_value_one());
	BIGNUM *jBN = BN_new();
	BN_dec2bn(&jBN, std::to_string(j).c_str());
	
	for(unsigned int m = 0; m < this->t; m++){
		// m == j continue;
		BIGNUM *mBN = BN_new();
		BN_dec2bn(&mBN, std::to_string(m).c_str());
		if(BN_cmp(jBN, mBN) == 0){
			continue;
		}

		// nomi = x - xm % p
		BIGNUM *nomi = BN_new();
		BN_mod_sub(nomi, x, shares.at(m).x, this->p, ctx);

		// denomi = xj -xm % p
		BIGNUM *denomi = BN_new();
		BN_mod_sub(denomi, shares.at(j).x, shares.at(m).x, this->p, ctx);

		// inverse = denomi ^ -1 % p
		BIGNUM *inverse = BN_new();
		BN_mod_inverse(inverse, denomi, this->p, ctx);

		// frac = nomi * inverse % p
		BIGNUM *frac = BN_new();
		BN_mod_mul(frac, nomi, inverse, this->p, ctx);

		// ret = temp * frac
		BIGNUM *temp = BN_dup(ret);
		BN_mod_mul(ret, temp, frac, this->p, ctx);
	}

	return ret;
}

// return the evaluation interpolated polynomial
BIGNUM *SSSS::lagrangeInterpolation(std::vector<Share> shares, BIGNUM *x){
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *ret = BN_new();

	for(unsigned int j = 0; j < this->t; j++){
		// mult = yj*lj(x)
		BIGNUM *mult = BN_new();
		BIGNUM *ljx = lagrangeBasePoly(shares, x, j);
		BN_mod_mul(mult, shares.at(j).y, ljx, this->p, ctx);

		// ret = temp + mult
		BIGNUM *temp = BN_dup(ret);
		BN_mod_add(ret, temp, mult, this->p, ctx);

		BN_free(mult);
		BN_free(ljx);
		BN_free(temp);
	}

	BN_CTX_free(ctx);
	return ret;
}

// lagrange interpolate over t shares
BIGNUM *SSSS::recoverSecret(std::vector<Share> shares){
	// assert different and all != 0 x of t shares
	if(!validShares(shares, this->t)){
		// TODO throw error
		return NULL;
	}

	return lagrangeInterpolation(shares, BN_new());
}
