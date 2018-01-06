#include "../system.h"

#include <openssl/evp.h>

#include "chacha-poly1305.h"
#include "../xalloc.h"

#define TAGLEN 16

struct chacha_poly1305_ctx {
	EVP_CIPHER_CTX *evp_cipher_ctx;
};

chacha_poly1305_ctx_t *chacha_poly1305_init(void) {
	chacha_poly1305_ctx_t *ctx = xzalloc(sizeof(*ctx));
	ctx->evp_cipher_ctx = EVP_CIPHER_CTX_new();
	return ctx;
}

void chacha_poly1305_exit(chacha_poly1305_ctx_t *ctx) {
	EVP_CIPHER_CTX_free(ctx->evp_cipher_ctx);
	free(ctx);
}

bool chacha_poly1305_set_key(chacha_poly1305_ctx_t *ctx, const void *key) {
	EVP_EncryptInit_ex(ctx->evp_cipher_ctx, EVP_chacha20_poly1305(), NULL, key, NULL);
	return true;
}

bool chacha_poly1305_encrypt(chacha_poly1305_ctx_t *ctx, uint64_t seqnr, const void *indata, size_t inlen, void *outdata, size_t *outlen) {
	int outlen_int;
	unsigned char* outdata_char = outdata;
	if(!EVP_EncryptUpdate(ctx->evp_cipher_ctx, outdata_char, &outlen_int, indata, inlen)) {
		return false;
	}
	outdata_char += outlen_int;
	if(!EVP_EncryptFinal_ex(ctx->evp_cipher_ctx, outdata_char, &outlen_int)) {
		return false;
	}
	outdata_char += outlen_int;
	if(!EVP_CIPHER_CTX_ctrl(ctx->evp_cipher_ctx, EVP_CTRL_AEAD_GET_TAG, TAGLEN, outdata_char)) {
		return false;
	}
	outdata_char += TAGLEN;
	if(outlen) *outlen = outdata_char - ((unsigned char*)outdata);
	return true;
}

bool chacha_poly1305_decrypt(chacha_poly1305_ctx_t *ctx, uint64_t seqnr, const void *indata, size_t inlen, void *outdata, size_t *outlen) {
	inlen -= TAGLEN;
	const unsigned char* indata_char = indata;
	if(!EVP_CIPHER_CTX_ctrl(ctx->evp_cipher_ctx, EVP_CTRL_AEAD_SET_TAG, TAGLEN, indata_char + inlen)) {
		return false;
	}

	int outlen_int;
	unsigned char* outdata_char = outdata;
	if(!EVP_DecryptUpdate(ctx->evp_cipher_ctx, outdata_char, &outlen_int, indata_char, inlen)) {
		return false;
	}
	outdata_char += outlen_int;
	if(!EVP_DecryptFinal_ex(ctx->evp_cipher_ctx, outdata_char, &outlen_int)) {
		return false;
	}
	outdata_char += outlen_int;
	if(outlen) *outlen = outdata_char - ((unsigned char*)outdata);
	return true;

}
