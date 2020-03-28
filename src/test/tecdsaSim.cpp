#include <openssl/ssl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include "../util/util.h"
#include "../tecdsa/tecdsa.h"
#include "../ecdsa/ecdsa.h"

int main(){
	// TODO create constructor with DKG

	// TECDSA
	// broadcast c = commit to g^privGamma
	// MtA with all other players
	// privDelta = privK * privGamma + sum(not your MtA shares of k*Gamma)
	// privSigma = privK * privKey + sum(not your MtA shares of k*privKey)
	// jointly calc privDelta and compute pubDelta ^ -1 (mod p)
	// jointly calc point R = multiply(c)^(pubDelta ^ -1)
	// set r of sig to x value of R
	// privS = m*privK + r*privSigma
	// jointly calc s = sum(privS)
	// sig = (r, s) (use the lower of s and -s mod p)

	std::string mess = "gilda";
	TECDSA sig0 = TECDSA(0, 2, 3);
	TECDSA sig1 = TECDSA(1, 2, 3);
	TECDSA sig2 = TECDSA(2, 2, 3);

	///////////////////// MtA k*Gamma /////////////////////
	sig0.leadKGammaMtA(1, sig1.getKGammaFollower());
	sig0.leadKGammaMtA(2, sig2.getKGammaFollower());
	sig1.leadKGammaMtA(2, sig2.getKGammaFollower());

	///////////////////// MtA k*priv /////////////////////
	sig0.leadKPrivMtA(1, sig1.getKPrivFollower());
	sig0.leadKPrivMtA(2, sig2.getKPrivFollower());
	sig1.leadKPrivMtA(2, sig2.getKPrivFollower());

	///////////////////// add deltas /////////////////////
	sig0.addDelta(sig0.getDelta());
	sig1.addDelta(sig0.getDelta());
	sig2.addDelta(sig0.getDelta());

	sig0.addDelta(sig1.getDelta());
	sig1.addDelta(sig1.getDelta());
	sig2.addDelta(sig1.getDelta());

	sig0.addDelta(sig2.getDelta());
	sig1.addDelta(sig2.getDelta());
	sig2.addDelta(sig2.getDelta());

	///////////////////// add gamma commitments /////////////////////
	sig0.addGammaCommitment(sig0.getPrivGammaCommitment());
	sig0.addGammaCommitment(sig1.getPrivGammaCommitment());
	sig0.addGammaCommitment(sig2.getPrivGammaCommitment());
	sig0.finalizeR();

	sig1.addGammaCommitment(sig0.getPrivGammaCommitment());
	sig1.addGammaCommitment(sig1.getPrivGammaCommitment());
	sig1.addGammaCommitment(sig2.getPrivGammaCommitment());
	sig1.finalizeR();

	sig2.addGammaCommitment(sig0.getPrivGammaCommitment());
	sig2.addGammaCommitment(sig1.getPrivGammaCommitment());
	sig2.addGammaCommitment(sig2.getPrivGammaCommitment());
	sig2.finalizeR();

	printf("sig0 r: %s\n", BN_bn2hex(sig0.getSig().first));
	printf("sig1 r: %s\n", BN_bn2hex(sig1.getSig().first));
	printf("sig2 r: %s\n\n", BN_bn2hex(sig2.getSig().first));

	///////////////////// add gamma commitments /////////////////////
	sig0.addPrivS(sig0.getPrivS((unsigned char *)mess.c_str(), mess.length()));
	sig0.addPrivS(sig1.getPrivS((unsigned char *)mess.c_str(), mess.length()));
	sig0.addPrivS(sig2.getPrivS((unsigned char *)mess.c_str(), mess.length()));

	sig1.addPrivS(sig0.getPrivS((unsigned char *)mess.c_str(), mess.length()));
	sig1.addPrivS(sig1.getPrivS((unsigned char *)mess.c_str(), mess.length()));
	sig1.addPrivS(sig2.getPrivS((unsigned char *)mess.c_str(), mess.length()));

	sig2.addPrivS(sig0.getPrivS((unsigned char *)mess.c_str(), mess.length()));
	sig2.addPrivS(sig1.getPrivS((unsigned char *)mess.c_str(), mess.length()));
	sig2.addPrivS(sig2.getPrivS((unsigned char *)mess.c_str(), mess.length()));

	printf("sig0 s: %s\n", BN_bn2hex(sig0.getSig().second));
	printf("sig1 s: %s\n", BN_bn2hex(sig1.getSig().second));
	printf("sig2 s: %s\n\n", BN_bn2hex(sig2.getSig().second));

	///////////////////// getting dkg keys and signing regularly /////////////////////
	sig0.dkg.addPrivateShare(1, sig1.dkg.getPrivateShare());
	sig0.dkg.addPrivateShare(2, sig2.dkg.getPrivateShare());
	sig0.dkg.addPublicKeyCommitment(1, sig1.dkg.getPublicKeyCommitment());
	sig0.dkg.addPublicKeyCommitment(2, sig2.dkg.getPublicKeyCommitment());

	BIGNUM *priKey = sig0.dkg.getPrivateKey();
	EC_POINT *pubKey = sig0.dkg.getPublicKey();
	EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
	EC_KEY_set_public_key(key, pubKey);
	EC_KEY_set_private_key(key, priKey);
	unsigned char *sig = ECDSA::sign(mess, key);
	printf("%s\n", (char *)sig);
	printf("%s%s\n\n", BN_bn2hex(sig2.getSig().first), BN_bn2hex(sig2.getSig().second));
	

	return 0;
}
