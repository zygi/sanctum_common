#include <cryptography.h>

__attribute__ ((always_inline,flatten)) inline static void int_hash(const void * in_data,
  size_t in_data_size,
  hash_t * out_hash) {

  // mdlen = hash output in bytes
  // digest goes to md
  sha3(in_data, in_data_size, out_hash, 32);
}

__attribute__ ((always_inline)) inline static void int_init_hash(hash_context_t * hash_context) {
  sha3_init(hash_context, 32);    // mdlen = hash output in bytes
}

__attribute__ ((always_inline)) inline static void int_extend_hash(hash_context_t * hash_context,
  const void * in_data,
  size_t in_data_size) {
  sha3_update(hash_context, in_data, in_data_size);
}

__attribute__ ((always_inline)) inline static void int_finalize_hash(hash_context_t * hash_context,
  hash_t * out_hash) {

  // digest goes to md
  sha3_final(out_hash, hash_context);
}

__attribute__ ((always_inline)) inline static void int_symmetric_encrypt(const void * in_plaintext,
  size_t in_message_size,
  const symmetric_key_t * in_key,
  const symmetric_public_data_t * in_public_values,
  void * out_ciphertext) {

  struct AES_ctx ctx;
  uint8_t buffer[in_message_size]; // CAUTION: the size should never be controlled by the adversary!
  memcpy(&buffer, in_plaintext, in_message_size);
  AES_init_ctx_iv(&ctx, in_key, in_public_values);
  AES_CTR_xcrypt_buffer(&ctx, &buffer, in_message_size);
}

__attribute__ ((always_inline)) inline static void int_symmetric_decrypt(const void * in_ciphertext,
  size_t in_message_size,
  const symmetric_key_t * in_key,
  const symmetric_public_data_t * in_public_values,
  void * out_plaintext) {

  struct AES_ctx ctx;
  uint8_t buffer[in_message_size]; // CAUTION: the size should never be controlled by the adversary!
  memcpy(buffer, in_ciphertext, in_message_size);
  AES_init_ctx_iv(&ctx, in_key, in_public_values);
  AES_CTR_xcrypt_buffer(&ctx, &buffer, in_message_size);
}

__attribute__ ((always_inline)) inline static void int_create_secret_signing_key(const key_seed_t * in_seed, secret_key_t * out_secret_key) {
  ed25519_create_privkey(out_secret_key, in_seed);
}

__attribute__ ((always_inline)) inline static void int_compute_public_signing_key(const secret_key_t * in_secret_key, const public_key_t * out_public_key) {
  ed25519_compute_pubkey(out_public_key, in_secret_key);
}

__attribute__ ((always_inline)) inline static void int_sign(void * in_data,
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


















__attribute__ ((flatten)) void hash(const void * in_data,
  size_t in_data_size,
  hash_t * out_hash) {
    int_hash(in_data, in_data_size, out_hash);
}

__attribute__ ((flatten)) void init_hash(hash_context_t * hash_context) {
  int_init_hash(hash_context);
}

__attribute__ ((flatten)) void extend_hash(hash_context_t * hash_context,
  const void * in_data,
  size_t in_data_size) {
    int_extend_hash(hash_context, in_data, in_data_size);
}

__attribute__ ((flatten)) void finalize_hash(hash_context_t * hash_context,
  hash_t * out_hash) {
int_finalize_hash(hash_context, out_hash);
}

__attribute__ ((flatten)) void symmetric_encrypt(const void * in_plaintext,
  size_t in_message_size,
  const symmetric_key_t * in_key,
  const symmetric_public_data_t * in_public_values,
  void * out_ciphertext) {
int_symmetric_encrypt(in_plaintext,
  in_message_size,
  in_key,
  in_public_values,
  out_ciphertext);
}

__attribute__ ((flatten)) void symmetric_decrypt(const void * in_ciphertext,
  size_t in_message_size,
  const symmetric_key_t * in_key,
  const symmetric_public_data_t * in_public_values,
  void * out_plaintext) {
int_symmetric_decrypt(in_ciphertext,
  in_message_size,
  in_key,
  in_public_values,
  out_plaintext);
}

__attribute__ ((flatten)) void create_secret_signing_key(const key_seed_t * in_seed, secret_key_t * out_secret_key) {
  int_create_secret_signing_key(in_seed, out_secret_key);
}

__attribute__ ((flatten)) void compute_public_signing_key(const secret_key_t * in_secret_key, const public_key_t * out_public_key) {
  int_compute_public_signing_key(in_secret_key, out_public_key);
}

__attribute__ ((flatten)) void sign(void * in_data,
  size_t in_data_size,
  public_key_t * in_public_key,
  secret_key_t * in_secret_key,
  signature_t * out_signature) {
    int_sign(in_data,
  in_data_size,
  in_public_key,
  in_secret_key,
  out_signature);
}