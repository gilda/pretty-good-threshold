#include "ecdh.h"

unsigned char *ECDH::computeKey(EC_KEY *key, EC_KEY *peerKey, unsigned long int len){
	int field_size;

	/* Calculate the size of the buffer for the shared secret */
	field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
	len = (field_size+7)/8;

	/* Allocate the memory for the shared secret */
	unsigned char *secret = new unsigned char[len];

	/* Derive the shared secret */
	len = ECDH_compute_key(secret, len, EC_KEY_get0_public_key(peerKey), key, NULL);

	if(len <= 0){
		return NULL;
	}

	// TODO when implemented return hash of secret
	return secret;
}
