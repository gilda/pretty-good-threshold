#pragma once
#include <openssl/evp.h>
#include <openssl/ec.h>
#include "../util/util.h" 

namespace ECDH{
	unsigned char *computeKey(EC_KEY *key, EC_KEY *peerKey, unsigned long int len);
}
