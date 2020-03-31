#include "util.h"

// TODO comment
// TODO error check
void initOpenSSL() {
	srand((unsigned)time(0));
	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
}

// TODO error check
void cleanupOpenSSL() {
	FIPS_mode_set(0);
	CRYPTO_set_locking_callback(nullptr);
	CRYPTO_set_id_callback(nullptr);
	SSL_COMP_free_compression_methods();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

void handleErrors(){
	ERR_print_errors_fp(stdout);
}

void handleErrorsNet(){
	perror("");
}

void handleErrors(const char *c){
	printf("%s", c);
	ERR_print_errors_fp(stdout);
}

void handleErrorsNet(const char *c){
	perror(c);
}

unsigned char *randomBytes(long unsigned int num){
	unsigned char *ret = new unsigned char[num];
	if(RAND_status() == 1){
		if(RAND_bytes(ret, num) == 0) handleErrors();
		return ret;
	}
	return NULL;	
}

unsigned char *randomPrivateBytes(long unsigned int num){
	unsigned char *ret = new unsigned char[num];
	if(RAND_status() == 1){
		if(RAND_priv_bytes(ret, num) == 0) handleErrors();
		return ret;
	}
	return NULL;
}

std::string encodeHex(unsigned char *data, unsigned int len){
	std::stringstream ss;
	for (unsigned int i = 0; i < len; i++) {
			ss << std::hex << std::setw(2) << std::setfill('0') << (int)(unsigned char)data[i];
	}
	return ss.str();
}
