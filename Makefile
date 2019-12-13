all: bin/ssss.o bin/vss.o bin/aes.o bin/util.o
	g++ -Wall src/main.cpp $^ -lssl -lcrypto -o bin/pretty-good-threshold

bin/util.o: src/util/util.h src/util/util.cpp
	g++ -c -Wall src/util/util.cpp -lssl -lcrypto -o bin/util.o
	
bin/ssss.o: src/ssss/ssss.h src/ssss/ssss.cpp
	g++ -c -Wall src/ssss/ssss.cpp -L./lib/ -lutil -lssl -lcrypto -o bin/ssss.o

bin/vss.o: src/vss/vss.h src/vss/vss.cpp
	g++ -c -Wall src/vss/vss.cpp -L./lib/ -lutil -lssl -lcrypto -o bin/vss.o

bin/aes.o: src/aes/aes.h src/aes/aes.cpp
	g++ -c -Wall src/aes/aes.cpp -L./lib/ -lutil -lssl -lcrypto -o bin/aes.o
