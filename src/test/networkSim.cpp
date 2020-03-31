#include <iostream>
#include "../network/server/server.h"

int main(){
	Server s = Server(5656, 256, 5);
	s.serve();
	return 0;
}