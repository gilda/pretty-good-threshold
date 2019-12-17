#pragma once
#include <openssl/sha.h>
#include "../util/util.h"

namespace HASH{
	unsigned char *sha256(unsigned char *data, unsigned int len);
}
