#pragma once
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void initOpenSSL();
void cleanupOpenSSL();
void handleErrors();
void handleErrorsNet();
void handleErrors(const char *c);
void handleErrorsNet(const char *c);
unsigned char *randomBytes(long unsigned int num);
unsigned char *randomPrivateBytes(long unsigned int num);
std::string encodeHex(unsigned char *data, unsigned int len);
