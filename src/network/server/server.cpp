#include "server.h"

Server::Server(unsigned int port, unsigned int maxBuffer, unsigned int maxPeers){
	this->port = port;
	this->numPeers = 0;
	this->maxPeers = maxPeers;
	this->maxBuffer = maxBuffer;
	this->buffer = new char[this->maxBuffer];

	this->serverSock = socket(AF_INET, SOCK_STREAM,  0);
	if(this->serverSock == -1) handleErrorsNet("socket() failed");

	this->setSocketReuse(this->serverSock);

	this->serverAddr.sin_family = AF_INET;
	this->serverAddr.sin_port = htons(port);
	this->serverAddr.sin_addr.s_addr = INADDR_ANY;

	int err = bind(this->serverSock, (sockaddr *)&this->serverAddr, sizeof(this->serverAddr));
	if(err == -1) handleErrorsNet("bind() failed");

	err = listen(this->serverSock, this->maxPeers);
	if(err == -1) handleErrorsNet("listen() failed");

	this->clientAddr = new sockaddr_in *[this->maxPeers];
	this->polling = new pollfd *[this->maxPeers + 1];
	for(unsigned int i = 0; i < this->maxPeers + 1; i++){
		this->polling[i] = new pollfd;
	}
	this->polling[0]->fd = this->serverSock;
	this->polling[0]->events = POLLIN;

}

void Server::setSocketReuse(int socket){
	int yes = 1;
	int err = setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	if(err == -1) handleErrorsNet("reuse socket failed");
}

void Server::addClient(int socket, sockaddr *addr){
	if(this->numPeers == this->maxPeers){
		return;
	}
	
	this->polling[this->numPeers + 1]->fd = socket;
	this->polling[this->numPeers + 1]->revents = POLLIN;
	this->clientAddr[this->numPeers] = (sockaddr_in *)addr;

	this->numPeers++;
}

void Server::removeClient(int socket){
	close(socket);
	for(unsigned int i = 0; i < this->numPeers; i++){
		if(this->polling[i + 1]->fd == socket){
			printf("removing %s\n", this->addrToString(this->clientAddr[i]).c_str());
			if(i == this->maxPeers){
				this->polling[i + 1] = NULL;
				this->clientAddr[i] = NULL;
				this->numPeers--;
				return;
			}else{
				this->polling[i + 1] = this->polling[this->numPeers + 1];
				this->clientAddr[i] = this->clientAddr[this->numPeers];
				this->numPeers--;
				return;
			}
		}
	}
}

std::string Server::addrToString(sockaddr_in *addr){
	std::string ret;
	char *addrBuf = new char[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(addr->sin_addr), addrBuf, INET_ADDRSTRLEN);
	ret = addrBuf;
	ret += ":" + std::to_string(ntohs(addr->sin_port));
	return ret;
}

void Server::flushBuffer(){
	std::memset(this->buffer, 0, this->maxBuffer);
}

void Server::serve(){
	int event;
	
	while(true){
		event = poll(this->polling[0], this->numPeers + 1, -1);
		if(event == -1) handleErrorsNet("poll failed");
		
		if(event == 0){
			// timeout
		}else if(event != -1){
			for(unsigned int i = 0; i < this->numPeers + 1; i++){
				if(polling[i]->revents & POLLIN){
					if(polling[i]->fd == this->serverSock){
						sockaddr client;
						unsigned int addrLen = sizeof(sockaddr);
						int socket = accept(this->serverSock, (sockaddr *)&client, &addrLen);
						if(socket == -1) handleErrorsNet("accept() failed");
						
						this->setSocketReuse(socket);
						this->addClient(socket, &client);
					}else{
						this->flushBuffer();
						int recvLen = recv(polling[i]->fd, this->buffer, this->maxBuffer, 0);
						if(recvLen == -1) handleErrorsNet("recv() failed");
						if(strcmp("close", this->buffer) == 0) this->removeClient(polling[i]->fd);
						
						// TODO
						// parse correct session ID and 
						// send to corrent handler
					}
				}
			}
		}
	}
}
