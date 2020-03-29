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
	// sig0
	sig0.setKGammaLeader();
	sig1.setKGammaFollower();
	TECDSA::doMtA(&sig0, &sig1);
	sig0.addPrivDelta(sig0.getCurrentLeader()->finalize());
	sig1.addPrivDelta(sig1.getCurrentFollower()->finalize());

	sig0.setKGammaLeader();
	sig2.setKGammaFollower();
	TECDSA::doMtA(&sig0, &sig2);
	sig0.addPrivDelta(sig0.getCurrentLeader()->finalize());
	sig2.addPrivDelta(sig2.getCurrentFollower()->finalize());

	// sig1
	sig1.setKGammaLeader();
	sig0.setKGammaFollower();
	TECDSA::doMtA(&sig1, &sig0);
	sig1.addPrivDelta(sig1.getCurrentLeader()->finalize());
	sig0.addPrivDelta(sig0.getCurrentFollower()->finalize());

	sig1.setKGammaLeader();
	sig2.setKGammaFollower();
	TECDSA::doMtA(&sig1, &sig2);
	sig1.addPrivDelta(sig1.getCurrentLeader()->finalize());
	sig2.addPrivDelta(sig2.getCurrentFollower()->finalize());

	// sig2
	sig2.setKGammaLeader();
	sig0.setKGammaFollower();
	TECDSA::doMtA(&sig2, &sig0);
	sig2.addPrivDelta(sig2.getCurrentLeader()->finalize());
	sig0.addPrivDelta(sig0.getCurrentFollower()->finalize());

	sig2.setKGammaLeader();
	sig1.setKGammaFollower();
	TECDSA::doMtA(&sig2, &sig1);
	sig2.addPrivDelta(sig2.getCurrentLeader()->finalize());
	sig1.addPrivDelta(sig1.getCurrentFollower()->finalize());

	///////////////////// MtA k*priv /////////////////////
	// sig0
	sig0.setKPrivLeader();
	sig1.setKPrivFollower();
	TECDSA::doMtA(&sig0, &sig1);
	sig0.addPrivSigma(sig0.getCurrentLeader()->finalize());
	sig1.addPrivSigma(sig1.getCurrentFollower()->finalize());

	sig0.setKPrivLeader();
	sig2.setKPrivFollower();
	TECDSA::doMtA(&sig0, &sig2);
	sig0.addPrivSigma(sig0.getCurrentLeader()->finalize());
	sig2.addPrivSigma(sig2.getCurrentFollower()->finalize());

	// sig1
	sig1.setKPrivLeader();
	sig0.setKPrivFollower();
	TECDSA::doMtA(&sig1, &sig0);
	sig1.addPrivSigma(sig1.getCurrentLeader()->finalize());
	sig0.addPrivSigma(sig0.getCurrentFollower()->finalize());

	sig1.setKPrivLeader();
	sig2.setKPrivFollower();
	TECDSA::doMtA(&sig1, &sig2);
	sig1.addPrivSigma(sig1.getCurrentLeader()->finalize());
	sig2.addPrivSigma(sig2.getCurrentFollower()->finalize());

	// sig2
	sig2.setKPrivLeader();
	sig0.setKPrivFollower();
	TECDSA::doMtA(&sig2, &sig0);
	sig2.addPrivSigma(sig2.getCurrentLeader()->finalize());
	sig0.addPrivSigma(sig0.getCurrentFollower()->finalize());

	sig2.setKPrivLeader();
	sig1.setKPrivFollower();
	TECDSA::doMtA(&sig2, &sig1);
	sig2.addPrivSigma(sig2.getCurrentLeader()->finalize());
	sig1.addPrivSigma(sig1.getCurrentFollower()->finalize());

	///////////////////// add all private deltas /////////////////////
	sig0.addDelta(sig0.getPrivDelta());
	sig0.addDelta(sig1.getPrivDelta());
	sig0.addDelta(sig2.getPrivDelta());

	sig1.addDelta(sig0.getPrivDelta());
	sig1.addDelta(sig1.getPrivDelta());
	sig1.addDelta(sig2.getPrivDelta());

	sig2.addDelta(sig0.getPrivDelta());
	sig2.addDelta(sig1.getPrivDelta());
	sig2.addDelta(sig2.getPrivDelta());

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
	
	printf("different signatures due to different k values, if both are valid we are OK!\n");
	printf("sign %s %s\n", (char *)sig, ECDSA::verify(mess, key, sig) ? "valid" : "invalid");
	printf("sig0 %s %s\n", sig0.getSig(), ECDSA::verify(mess, key, sig0.getSig()) ? "valid" : "invalid");
	printf("sig1 %s %s\n", sig1.getSig(), ECDSA::verify(mess, key, sig1.getSig()) ? "valid" : "invalid");
	printf("sig2 %s %s\n", sig2.getSig(), ECDSA::verify(mess, key, sig2.getSig()) ? "valid" : "invalid");
	
	return 0;
}
