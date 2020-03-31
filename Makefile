SOURCE = bin/ssss.o bin/vss.o bin/aes.o bin/ecdh.o bin/ecies.o bin/sha256.o bin/ecdsa.o bin/pcommit.o bin/dkg.o bin/ot.o bin/mta.o bin/tecdsa.o bin/util.o bin/network/server.o

test: testComponents testDKG testTECDSA testNet

testComponents: $(SOURCE)
	g++ -Wall src/test/components.cpp $^ -lssl -lcrypto -o bin/test/components

testDKG: $(SOURCE)
	g++ -Wall src/test/dkgSim.cpp $^ -lssl -lcrypto -o bin/test/dkgSim

testTECDSA: $(SOURCE)
	g++ -Wall src/test/tecdsaSim.cpp $^ -lssl -lcrypto -o bin/test/tecdsaSim

testNet: $(SOURCE)
	g++ -Wall src/test/networkSim.cpp $^ -lssl -lcrypto -o bin/test/networkSim

bin/util.o: src/util/util.h src/util/util.cpp
	g++ -c -Wall src/util/util.cpp -lssl -lcrypto -o bin/util.o
	
bin/ssss.o: src/ssss/ssss.h src/ssss/ssss.cpp
	g++ -c -Wall src/ssss/ssss.cpp -lssl -lcrypto -o bin/ssss.o

bin/vss.o: src/vss/vss.h src/vss/vss.cpp
	g++ -c -Wall src/vss/vss.cpp -lssl -lcrypto -o bin/vss.o

bin/aes.o: src/aes/aes.h src/aes/aes.cpp
	g++ -c -Wall src/aes/aes.cpp -lssl -lcrypto -o bin/aes.o

bin/ecdh.o: src/ecdh/ecdh.h src/ecdh/ecdh.cpp
	g++ -c -Wall src/ecdh/ecdh.cpp -lssl -lcrypto -o bin/ecdh.o

bin/ecies.o: src/ecies/ecies.h src/ecies/ecies.cpp
	g++ -c -Wall src/ecies/ecies.cpp -lssl -lcrypto -o bin/ecies.o

bin/sha256.o: src/sha256/sha256.h src/sha256/sha256.cpp
	g++ -c -Wall src/sha256/sha256.cpp -lssl -lcrypto -o bin/sha256.o

bin/ecdsa.o: src/ecdsa/ecdsa.h src/ecdsa/ecdsa.cpp
	g++ -c -Wall src/ecdsa/ecdsa.cpp -lssl -lcrypto -o bin/ecdsa.o

bin/pcommit.o: src/pcommit/pcommit.h src/pcommit/pcommit.cpp
	g++ -c -Wall src/pcommit/pcommit.cpp -lssl -lcrypto -o bin/pcommit.o

bin/dkg.o: src/dkg/dkg.h src/dkg/dkg.cpp
	g++ -c -Wall src/dkg/dkg.cpp -lssl -lcrypto -o bin/dkg.o

bin/ot.o: src/ot/ot.h src/ot/ot.cpp
	g++ -c -Wall src/ot/ot.cpp -lssl -lcrypto -o bin/ot.o

bin/mta.o: src/mta/mta.h src/mta/mta.cpp
	g++ -c -Wall src/mta/mta.cpp -lssl -lcrypto -o bin/mta.o

bin/tecdsa.o: src/tecdsa/tecdsa.h src/tecdsa/tecdsa.cpp
	g++ -c -Wall src/tecdsa/tecdsa.cpp -lssl -lcrypto -o bin/tecdsa.o

bin/network/server.o: src/network/server/server.h src/network/server/server.cpp
	g++ -c -Wall src/network/server/server.cpp -o bin/network/server.o