all: bin/ssss.o bin/vss.o bin/aes.o bin/ecdh.o bin/ecies.o bin/sha256.o bin/ecdsa.o bin/util.o
	g++ -Wall src/main.cpp $^ -lssl -lcrypto -o bin/pretty-good-threshold

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
