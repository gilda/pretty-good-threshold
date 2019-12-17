#pragma once
#include <cstring>
#include <openssl/ecdsa.h>
#include "../util/util.h"
#include "../sha256/sha256.h"

namespace ECDSA{
	unsigned char *sign(unsigned char *data, unsigned int len, EC_KEY *key);
	bool verify(unsigned char *data, unsigned int len, EC_KEY *key, unsigned char *signature);
}
