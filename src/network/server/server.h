#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <cstring>
#include "../../util/util.h"

class Server{
	private:
		unsigned int port;
		unsigned int maxPeers;
		int serverSock;
		char *buffer;
		unsigned int maxBuffer;
		unsigned int numPeers;
		sockaddr_in serverAddr;
		sockaddr_in **clientAddr;
		pollfd **polling;

		void setSocketReuse(int socket);
		void addClient(int socket, sockaddr *addr);
		void removeClient(int socket);
		std::string addrToString(sockaddr_in *addr);
		void flushBuffer();

	public:
		Server(unsigned int port, unsigned int maxBuffer, unsigned int maxPeers);
		void serve();
};
