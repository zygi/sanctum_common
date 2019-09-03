#include "cryptography.h"

void hash(const void * in_data,
  size_t in_data_size,
  hash_t * out_hash) {

  // mdlen = hash output in bytes
  // digest goes to md
  sha3(in_data, in_data_size, out_hash, 32);
}

void init_hash(hash_context_t * hash_context) {
  sha3_init(hash_context, 32);    // mdlen = hash output in bytes
}

void extend_hash(hash_context_t * hash_context,
  const void * in_data,
  size_t in_data_size) {
  sha3_update(hash_context, in_data, in_data_size);
}

void finalize_hash(hash_context_t * hash_context,
  hash_t * out_hash) {

  // digest goes to md
  sha3_final(out_hash, hash_context);
}

void create_secret_signing_key(const key_seed_t * in_seed, secret_key_t * out_secret_key) {
  ed25519_create_privkey(out_secret_key, in_seed);
}

void compute_public_signing_key(const secret_key_t * in_secret_key, const public_key_t * out_public_key) {
  ed25519_compute_pubkey(out_public_key, in_secret_key);
}

void sign(void * in_data,
  size_t in_data_size,
  public_key_t * in_public_key,
  secret_key_t * in_secret_key,
  signature_t * out_signature) {
    
  ed25519_sign(out_signature,
    in_data,
    in_data_size,
    in_public_key,
    in_secret_key);
}
