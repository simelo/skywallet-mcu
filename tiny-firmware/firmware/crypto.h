
#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "messages.pb.h"
#include "coins.h"
#include "hasher.h"

#define ser_length_size(len) ((len) < 253 ? 1 : (len) < 0x10000 ? 3 : 5)

const HDNode *cryptoMultisigPubkey(const CoinInfo *coin, const MultisigRedeemScriptType *multisig, uint32_t index);
uint32_t ser_length(uint32_t len, uint8_t *out);
uint32_t cryptoMultisigPubkeyCount(const MultisigRedeemScriptType *multisig);
int cryptoMultisigPubkeyIndex(const CoinInfo *coin, const MultisigRedeemScriptType *multisig, const uint8_t *pubkey);
int cryptoMultisigFingerprint(const MultisigRedeemScriptType *multisig, uint8_t *hash);
uint32_t ser_length_hash(Hasher *hasher, uint32_t len);

#endif