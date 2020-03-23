#pragma once
#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../util/util.h"
#include "../sha256/sha256.h"

namespace PCommitment{
	EC_POINT *getH();
	EC_POINT *commit(BIGNUM *value, BIGNUM *rand);
	bool verify(BIGNUM *value, BIGNUM *rand, EC_POINT *commitment);
}
