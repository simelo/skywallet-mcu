
#include "crypto.h"
#include "sha2.h"
#include "hasher.h"
#include "bip32.h"
#include "coins.h"
#include "layout.h"

uint32_t ser_length(uint32_t len, uint8_t *out) {
  if (len < 253) {
    out[0] = len & 0xFF;
    return 1;
  }
  if (len < 0x10000) {
    out[0] = 253;
    out[1] = len & 0xFF;
    out[2] = (len >> 8) & 0xFF;
    return 3;
  }
  out[0] = 254;
  out[1] = len & 0xFF;
  out[2] = (len >> 8) & 0xFF;
  out[3] = (len >> 16) & 0xFF;
  out[4] = (len >> 24) & 0xFF;
  return 5;
}

const HDNode *cryptoMultisigPubkey(const CoinInfo *coin,
                                   const MultisigRedeemScriptType *multisig,
                                   uint32_t index) {
  const HDNodeType *node_ptr;
  const uint32_t *address_n;
  uint32_t address_n_count;
  if (multisig->nodes_count) {  // use multisig->nodes
    if (index >= multisig->nodes_count) {
      return 0;
    }
    node_ptr = &(multisig->nodes[index]);
    address_n = multisig->address_n;
    address_n_count = multisig->address_n_count;
  } else if (multisig->pubkeys_count) {  // use multisig->pubkeys
    if (index >= multisig->pubkeys_count) {
      return 0;
    }
    node_ptr = &(multisig->pubkeys[index].node);
    address_n = multisig->pubkeys[index].address_n;
    address_n_count = multisig->pubkeys[index].address_n_count;
  } else {
    return 0;
  }
  if (node_ptr->chain_code.size != 32) return 0;
  if (!node_ptr->has_public_key || node_ptr->public_key.size != 33) return 0;
  static HDNode node;
  if (!hdnode_from_xpub(node_ptr->depth, node_ptr->child_num,
                        node_ptr->chain_code.bytes, node_ptr->public_key.bytes,
                        coin->curve_name, &node)) {
    return 0;
  }
  layoutProgressUpdate(true);
  for (uint32_t i = 0; i < address_n_count; i++) {
    if (!hdnode_public_ckd(&node, address_n[i])) {
      return 0;
    }
    layoutProgressUpdate(true);
  }
  return &node;
}

uint32_t cryptoMultisigPubkeyCount(const MultisigRedeemScriptType *multisig) {
  return multisig->nodes_count ? multisig->nodes_count
                               : multisig->pubkeys_count;
}

int cryptoMultisigPubkeyIndex(const CoinInfo *coin,
                              const MultisigRedeemScriptType *multisig,
                              const uint8_t *pubkey) {
  for (size_t i = 0; i < cryptoMultisigPubkeyCount(multisig); i++) {
    const HDNode *pubnode = cryptoMultisigPubkey(coin, multisig, i);
    if (pubnode && memcmp(pubnode->public_key, pubkey, 33) == 0) {
      return i;
    }
  }
  return -1;
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