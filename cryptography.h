#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H

// Hash
#include <sha3/sha3.h>

typedef struct hash_t { uint8_t x[32]; } hash_t;
typedef sha3_ctx_t hash_context_t;

void hash(const void * in_data,
  size_t in_data_size,
  hash_t * out_hash) __attribute__((flatten));

void init_hash(hash_context_t * hash_context) __attribute__((flatten));

void finalize_hash(hash_context_t * hash_context,
  hash_t * out_hash) __attribute__((flatten));


#define CBC 0
#define ECB 0
#define CTR 1
#define AES256 1
#include <aes/aes.h>

#include <string.h>
// Provides memcpy
 
typedef struct symmetric_key_t { uint8_t x[AES_KEYLEN]; } symmetric_key_t;
typedef struct symmetric_public_data_t { uint8_t x[AES_BLOCKLEN]; } symmetric_public_data_t;

void symmetric_encrypt(const void * in_plaintext,
  size_t in_message_size,
  const symmetric_key_t * in_key,
  const symmetric_public_data_t * in_public_values,
  void * out_ciphertext) __attribute__((flatten));

void symmetric_decrypt(const void * in_ciphertext,
  size_t in_message_size,
  const symmetric_key_t * in_key,
  const symmetric_public_data_t * in_public_values,
  void * out_plaintext) __attribute__((flatten));

// Signatures

#define ED25519_NO_SEED 1
#include <ed25519/ed25519.h>

typedef struct public_key_seed_t { uint8_t x[32]; } key_seed_t;
typedef struct public_key_t { uint8_t x[32]; } public_key_t;
typedef struct secret_key_t { uint8_t x[64]; } secret_key_t;
typedef struct signature_t { uint8_t x[64]; } signature_t;

void create_secret_signing_key(const key_seed_t * in_seed, secret_key_t * out_secret_key) __attribute__((flatten));

void compute_public_signing_key(const secret_key_t * in_secret_key, const public_key_t * out_public_key) __attribute__((flatten));

void sign(void * in_data,
  size_t in_data_size,
  public_key_t * in_public_key,
  secret_key_t * in_secret_key,
  signature_t * out_signature) __attribute__((flatten));

#endif
