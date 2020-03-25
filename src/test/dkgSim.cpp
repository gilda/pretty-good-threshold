#include "../util/util.h"
#include "../dkg/dkg.h"

int main(){
	initOpenSSL();

	// TODO
	// create accumulator functions for DKG
	// create a dkg simulation

	DKG dkg1 = DKG(0, 2, 3);
	DKG dkg2 = DKG(1, 2, 3);
	DKG dkg3 = DKG(2, 2, 3);

	///////////////////// Getting Commitments /////////////////////
	// dkg1 commitments
	dkg2.addNodeCommitments(0, dkg1.getCommitments());
	dkg3.addNodeCommitments(0, dkg1.getCommitments());

	// dkg2 commitments
	dkg1.addNodeCommitments(1, dkg2.getCommitments());
	dkg3.addNodeCommitments(1, dkg2.getCommitments());

	// dkg1 commitments
	dkg1.addNodeCommitments(2, dkg3.getCommitments());
	dkg2.addNodeCommitments(2, dkg3.getCommitments());

	///////////////////// Getting Shares /////////////////////
	
	// dkg1 shares
	dkg1.addNodeShare(1, dkg2.getShare(0));
	dkg1.addNodeShare(2, dkg3.getShare(0));
	
	// dkg2 shares
	dkg2.addNodeShare(0, dkg1.getShare(1));
	dkg2.addNodeShare(2, dkg3.getShare(1));

	// dkg3 shares
	dkg3.addNodeShare(0, dkg1.getShare(2));
	dkg3.addNodeShare(1, dkg2.getShare(2));	

	///////////////////// Verifying Shares /////////////////////
	printf("dkg1 share #2 is %s\n", dkg1.verifyShare(1) ? "valid" : "invalid");
	printf("dkg1 share #3 is %s\n", dkg1.verifyShare(2) ? "valid" : "invalid");

	printf("dkg2 share #1 is %s\n", dkg2.verifyShare(0) ? "valid" : "invalid");
	printf("dkg2 share #3 is %s\n", dkg2.verifyShare(2) ? "valid" : "invalid");

	printf("dkg3 share #1 is %s\n", dkg2.verifyShare(0) ? "valid" : "invalid");
	printf("dkg3 share #2 is %s\n\n", dkg2.verifyShare(1) ? "valid" : "invalid");

	///////////////////// Getting Public Key Commitments /////////////////////
	dkg1.addPublicKeyCommitment(1 ,dkg2.getPublicKeyCommitment());
	dkg1.addPublicKeyCommitment(2, dkg3.getPublicKeyCommitment());

	dkg2.addPublicKeyCommitment(0 ,dkg1.getPublicKeyCommitment());
	dkg2.addPublicKeyCommitment(2, dkg3.getPublicKeyCommitment());

	dkg3.addPublicKeyCommitment(0 ,dkg1.getPublicKeyCommitment());
	dkg3.addPublicKeyCommitment(1, dkg2.getPublicKeyCommitment());
	
	///////////////////// Getting Public Key /////////////////////

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	printf("dkg1 public Key: %s\n", EC_POINT_point2hex(group, dkg1.getPublicKey(), POINT_CONVERSION_COMPRESSED, NULL));
	printf("dkg2 public Key: %s\n", EC_POINT_point2hex(group, dkg2.getPublicKey(), POINT_CONVERSION_COMPRESSED, NULL));
	printf("dkg3 public Key: %s\n\n", EC_POINT_point2hex(group, dkg3.getPublicKey(), POINT_CONVERSION_COMPRESSED, NULL));

	///////////////////// Getting Private Key Shares /////////////////////
	dkg1.addPrivateShare(1, dkg2.getPrivateShare());
	dkg1.addPrivateShare(2, dkg3.getPrivateShare());

	dkg2.addPrivateShare(0, dkg1.getPrivateShare());
	dkg2.addPrivateShare(2, dkg3.getPrivateShare());

	dkg3.addPrivateShare(0, dkg1.getPrivateShare());
	dkg3.addPrivateShare(1, dkg2.getPrivateShare());

	///////////////////// Getting Private Key /////////////////////
	printf("dkg1 Private Key: %s\n", BN_bn2hex(dkg1.getPrivateKey()));
	printf("dkg2 Private Key: %s\n", BN_bn2hex(dkg2.getPrivateKey()));
	printf("dkg3 Private Key: %s\n\n", BN_bn2hex(dkg3.getPrivateKey()));

	///////////////////// Verifying Public Private Keys /////////////////////
	EC_POINT *publicKey = EC_POINT_new(group);
	EC_POINT_mul(group, publicKey, dkg1.getPrivateKey(), NULL, NULL, NULL);
	printf("public from private: %s\n", EC_POINT_point2hex(group, publicKey, POINT_CONVERSION_COMPRESSED, NULL));

	cleanupOpenSSL();
	return 0;
}
