#include <iostream>
#include "ssss/ssss.h"
#include "vss/vss.h"
#include "aes/aes.h"
#include "util/util.h"

int main(){
	initOpenSSL();

	BIGNUM *a = BN_new();
	BN_hex2bn(&a, "6");

	SSSS gilda = SSSS(3, 5, a);
	std::vector<Share> points = gilda.getShares();
	
	for(auto it = points.begin(); it != points.end(); it++){
		printf("x = %s, y = %s\n", BN_bn2hex(it->x), BN_bn2hex(it->y));
	}

	printf("f(0) = %s\n\n", BN_bn2hex(gilda.recoverSecret(points)));

	VSS feld = VSS(4, 5, BN_dup(a));
	Share fake;
	fake.x = BN_new();
	fake.y = BN_new();
	BN_one(fake.y);
	feld.verifyShare(fake);

	cleanupOpenSSL();
	return 0;
}
