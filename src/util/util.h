#pragma once
#include <openssl/ssl.h>
#include <openssl/err.h>

void initOpenSSL();
void cleanupOpenSSL();
void handleErrors();
