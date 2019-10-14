#ifndef __TRANSACTION_H__
#define __TRANSACTION_H__

#include <stdbool.h>
#include <stdint.h>
#include "hasher.h"

#define TX_OVERWINTERED 0x80000000

typedef struct {
  uint32_t inputs_len;
  uint32_t outputs_len;

  uint32_t version;
  uint32_t version_group_id;
  uint32_t lock_time;
  uint32_t expiry;
  bool is_segwit;
  bool is_decred;

  uint32_t have_inputs;
  uint32_t have_outputs;

  bool overwintered;
  uint32_t extra_data_len;
  uint32_t extra_data_received;

  uint32_t size;

  Hasher hasher;
} TxStruct;

void tx_init(TxStruct *tx, uint32_t inputs_len, uint32_t outputs_len,
             uint32_t version, uint32_t lock_time, uint32_t expiry,
             uint32_t extra_data_len, HasherType hasher_sign, bool overwintered,
             uint32_t version_group_id);

uint32_t tx_prevout_hash(Hasher *hasher, const TxInputType *input);
uint32_t tx_serialize_extra_data_hash(TxStruct *tx, const uint8_t *data, uint32_t datalen);
#endif