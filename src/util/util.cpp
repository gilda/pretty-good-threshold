#include "util.h"

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

void handleErros(){
	ERR_print_errors_fp(stdout);
}
