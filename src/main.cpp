#include <iostream>
#include "ssss/ssss.h"
#include "util/util.h"

int main(){
	initOpenSSL();

	BIGNUM *a = BN_new();
	BN_hex2bn(&a, "6");
	SSSS gilda = SSSS(3, 5, a);
	std::vector<Share> points = gilda.generateShares();
	
	for(auto it = points.begin(); it != points.end(); it++){
		printf("x = %s, y = %s\n", BN_bn2hex(it->x), BN_bn2hex(it->y));
	}

	printf("f(0) = %s\n", BN_bn2hex(gilda.recoverSecret(points)));

	cleanupOpenSSL();
	return 0;
}
