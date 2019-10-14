#ifndef __BITCOIN_SIGNING_H__
#define __BITCOIN_SIGNING_H__

#include "messages.pb.h"
#include "coins.h"

void bitcoin_signing_init(const BitcoinSignTx *msg, const CoinInfo *_coin, const HDNode *_root);
void bitcoin_signing_txack(BitcoinTxAck_TransactionType *tx);

#endif