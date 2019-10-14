
#include "crypto.h"
#include "sha2.h"
#include "hasher.h"

uint32_t cryptoMultisigPubkeyCount(const MultisigRedeemScriptType *multisig) {
  return multisig->nodes_count ? multisig->nodes_count
                               : multisig->pubkeys_count;
}

int cryptoMultisigFingerprint(const MultisigRedeemScriptType *multisig, uint8_t *hash) {
  static const HDNodeType *pubnodes[15], *swap;
  const uint32_t n = cryptoMultisigPubkeyCount(multisig);
  if (n < 1 || n > 15) {
    return 0;
  }
  if (!multisig->has_m || multisig->m < 1 || multisig->m > 15) {
    return 0;
  }
  for (uint32_t i = 0; i < n; i++) {
    if (multisig->nodes_count) {  // use multisig->nodes
      pubnodes[i] = &(multisig->nodes[i]);
    } else if (multisig->pubkeys_count) {  // use multisig->pubkeys
      pubnodes[i] = &(multisig->pubkeys[i].node);
    } else {
      return 0;
    }
  }
  for (uint32_t i = 0; i < n; i++) {
    if (!pubnodes[i]->has_public_key || pubnodes[i]->public_key.size != 33)
      return 0;
    if (pubnodes[i]->chain_code.size != 32) return 0;
  }
  // minsort according to pubkey
  for (uint32_t i = 0; i < n - 1; i++) {
    for (uint32_t j = n - 1; j > i; j--) {
      if (memcmp(pubnodes[i]->public_key.bytes, pubnodes[j]->public_key.bytes,
                 33) > 0) {
        swap = pubnodes[i];
        pubnodes[i] = pubnodes[j];
        pubnodes[j] = swap;
      }
    }
  }
  // hash sorted nodes
  SHA256_CTX ctx;
  sha256_Init(&ctx);
  sha256_Update(&ctx, (const uint8_t *)&(multisig->m), sizeof(uint32_t));
  for (uint32_t i = 0; i < n; i++) {
    sha256_Update(&ctx, (const uint8_t *)&(pubnodes[i]->depth),
                  sizeof(uint32_t));
    sha256_Update(&ctx, (const uint8_t *)&(pubnodes[i]->fingerprint),
                  sizeof(uint32_t));
    sha256_Update(&ctx, (const uint8_t *)&(pubnodes[i]->child_num),
                  sizeof(uint32_t));
    sha256_Update(&ctx, pubnodes[i]->chain_code.bytes, 32);
    sha256_Update(&ctx, pubnodes[i]->public_key.bytes, 33);
  }
  sha256_Update(&ctx, (const uint8_t *)&n, sizeof(uint32_t));
  sha256_Final(&ctx, hash);
  layoutProgressUpdate(true);
  return 1;
}

uint32_t ser_length_hash(Hasher *hasher, uint32_t len) {
  if (len < 253) {
    hasher_Update(hasher, (const uint8_t *)&len, 1);
    return 1;
  }
  if (len < 0x10000) {
    uint8_t d = 253;
    hasher_Update(hasher, &d, 1);
    hasher_Update(hasher, (const uint8_t *)&len, 2);
    return 3;
  }
  uint8_t d = 254;
  hasher_Update(hasher, &d, 1);
  hasher_Update(hasher, (const uint8_t *)&len, 4);
  return 5;
}