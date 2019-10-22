
#ifndef __SIGNING_H__
#define __SIGNING_H__

#include <stdbool.h>
#include <stdint.h>
#include "bip32.h"
#include "coins.h"
#include "hasher.h"
#include "messages.pb.h"

void bitcoin_signing_init(const BitcoinSignTx *msg, const CoinInfo *_coin,
                  const HDNode *_root);
void signing_abort(void);
void bitcoin_signing_txack(BitcoinTxAck_TransactionType *tx);

#endif
