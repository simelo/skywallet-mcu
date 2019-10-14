
#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "messages.pb.h"

#define ser_length_size(len) ((len) < 253 ? 1 : (len) < 0x10000 ? 3 : 5)

int cryptoMultisigFingerprint(const MultisigRedeemScriptType *multisig, uint8_t *hash);
uint32_t ser_length_hash(Hasher *hasher, uint32_t len);

#endif