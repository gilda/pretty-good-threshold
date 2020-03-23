#include "pcommit.h"

EC_POINT *PCommitment::getH(){
	unsigned char *charX = HASH::sha256("PedersenCommitment");
	
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();

	BIGNUM *x = BN_bin2bn(charX, 32, NULL);
	if(x == NULL) handleErrors();

	EC_POINT *h = EC_POINT_new(group);
	if(h == NULL) handleErrors();

	int err = EC_POINT_set_compressed_coordinates(group, h, x, 0, ctx);
	if(err == 0) handleErrors();

	return h;
}

EC_POINT *PCommitment::commit(BIGNUM *value, BIGNUM *rand){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();
	
	EC_POINT *commitment = EC_POINT_new(group);
	if(commitment == NULL) handleErrors();

	// commitment = g^value*h^rand
	int err = EC_POINT_mul(group, commitment, value, PCommitment::getH(), rand, ctx);
	if(err == 0) handleErrors();

	return commitment;
}

bool PCommitment::verify(BIGNUM *value, BIGNUM *rand, EC_POINT *commitment){
	BN_CTX *ctx = BN_CTX_new();
	if(ctx == NULL) handleErrors();

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	if(group == NULL) handleErrors();

	int out = EC_POINT_cmp(group, commitment, PCommitment::commit(value, rand), ctx);
	if(out == -1) handleErrors();

	return out == 0;
}
