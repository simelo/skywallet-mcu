#include "transaction.h"
#include "messages.pb.h"
#include "coins.h"
#include "crypto.h"
#include "layout2.h"
#include "protect.h"

#define SEGWIT_VERSION_0 0

#define CASHADDR_P2KH (0)
#define CASHADDR_P2SH (8)
#define CASHADDR_160 (0)

/* transaction input size (without script): 32 prevhash, 4 idx, 4 sequence */
#define TXSIZE_INPUT 40
/* transaction output size (without script): 8 amount */
#define TXSIZE_OUTPUT 8
/* size of a pubkey */
#define TXSIZE_PUBKEY 33
/* size of a DER signature (3 type bytes, 3 len bytes, 33 R, 32 S, 1 sighash */
#define TXSIZE_SIGNATURE 72
/* size of a multiscript without pubkey (1 M, 1 N, 1 checksig) */
#define TXSIZE_MULTISIGSCRIPT 3
/* size of a p2wpkh script (1 version, 1 push, 20 hash) */
#define TXSIZE_WITNESSPKHASH 22
/* size of a p2wsh script (1 version, 1 push, 32 hash) */
#define TXSIZE_WITNESSSCRIPT 34
/* size of a p2pkh script (dup, hash, push, 20 pubkeyhash, equal, checksig) */
#define TXSIZE_P2PKHASH 25
/* size of a p2sh script (hash, push, 20 scripthash, equal) */
#define TXSIZE_P2SCRIPT 23
/* size of a Decred witness (without script): 8 amount, 4 block height, 4 block
 * index */
#define TXSIZE_DECRED_WITNESS 16

static const uint8_t segwit_header[2] = {0, 1};

static inline uint32_t op_push_size(uint32_t i) {
  if (i < 0x4C) {
    return 1;
  }
  if (i < 0x100) {
    return 2;
  }
  if (i < 0x10000) {
    return 3;
  }
  return 5;
}

void tx_init(TxStruct *tx, uint32_t inputs_len, uint32_t outputs_len,
             uint32_t version, uint32_t lock_time, uint32_t expiry,
             uint32_t extra_data_len, HasherType hasher_sign, bool overwintered,
             uint32_t version_group_id) {
  tx->inputs_len = inputs_len;
  tx->outputs_len = outputs_len;
  tx->version = version;
  tx->lock_time = lock_time;
  tx->expiry = expiry;
  tx->have_inputs = 0;
  tx->have_outputs = 0;
  tx->extra_data_len = extra_data_len;
  tx->extra_data_received = 0;
  tx->size = 0;
  tx->is_segwit = false;
  tx->is_decred = false;
  tx->overwintered = overwintered;
  tx->version_group_id = version_group_id;
  hasher_Init(&(tx->hasher), hasher_sign);
}

void tx_hash_final(TxStruct *t, uint8_t *hash, bool reverse) {
  hasher_Final(&(t->hasher), hash);
  if (!reverse) return;
  for (uint8_t i = 0; i < 16; i++) {
    uint8_t k = hash[31 - i];
    hash[31 - i] = hash[i];
    hash[i] = k;
  }
}

uint32_t tx_prevout_hash(Hasher *hasher, const TxInputType *input) {
  for (int i = 0; i < 32; i++) {
    hasher_Update(hasher, &(input->prev_hash.bytes[31 - i]), 1);
  }
  hasher_Update(hasher, (const uint8_t *)&input->prev_index, 4);
  return 36;
}

uint32_t tx_sequence_hash(Hasher *hasher, const TxInputType *input) {
  hasher_Update(hasher, (const uint8_t *)&input->sequence, 4);
  return 4;
}

static uint32_t tx_input_script_size(const TxInputType *txinput) {
  uint32_t input_script_size;
  if (txinput->has_multisig) {
    uint32_t multisig_script_size = TXSIZE_MULTISIGSCRIPT + txinput->multisig.pubkeys_count * (1 + TXSIZE_PUBKEY);
    input_script_size = 1  // the OP_FALSE bug in multisig
                        + txinput->multisig.m * (1 + TXSIZE_SIGNATURE) +
                        op_push_size(multisig_script_size) +
                        multisig_script_size;
  } else {
    input_script_size = (1 + TXSIZE_SIGNATURE + 1 + TXSIZE_PUBKEY);
  }

  return input_script_size;
}

uint32_t tx_input_weight(const CoinInfo *coin, const TxInputType *txinput) {
  (void)coin;

  uint32_t input_script_size = tx_input_script_size(txinput);
  uint32_t weight = 4 * TXSIZE_INPUT;
  if (txinput->script_type == InputScriptType_SPENDADDRESS ||
      txinput->script_type == InputScriptType_SPENDMULTISIG) {
    input_script_size += ser_length_size(input_script_size);
    weight += 4 * input_script_size;
  } else if (txinput->script_type == InputScriptType_SPENDWITNESS ||
             txinput->script_type == InputScriptType_SPENDP2SHWITNESS) {
    if (txinput->script_type == InputScriptType_SPENDP2SHWITNESS) {
      weight += 4 * (2 + (txinput->has_multisig ? TXSIZE_WITNESSSCRIPT
                                                : TXSIZE_WITNESSPKHASH));
    } else {
      weight += 4;  // empty input script
    }
    weight += input_script_size;  // discounted witness
  }
  return weight;
}

uint32_t tx_script_hash(Hasher *hasher, uint32_t size, const uint8_t *data) {
  int r = ser_length_hash(hasher, size);
  hasher_Update(hasher, data, size);
  return r + size;
}

uint32_t tx_serialize_header_hash(TxStruct *tx) {
  int r = 4;
  if (tx->overwintered) {
    uint32_t ver = tx->version | TX_OVERWINTERED;
    hasher_Update(&(tx->hasher), (const uint8_t *)&ver, 4);
    hasher_Update(&(tx->hasher), (const uint8_t *)&(tx->version_group_id), 4);
    r += 4;
  } else {
    hasher_Update(&(tx->hasher), (const uint8_t *)&(tx->version), 4);
    if (tx->is_segwit) {
      hasher_Update(&(tx->hasher), segwit_header, 2);
      r += 2;
    }
  }
  return r + ser_length_hash(&(tx->hasher), tx->inputs_len);
}

uint32_t tx_serialize_input_hash(TxStruct *tx, const TxInputType *input) {
  if (tx->have_inputs >= tx->inputs_len) {
    // already got all inputs
    return 0;
  }
  uint32_t r = 0;
  if (tx->have_inputs == 0) {
    r += tx_serialize_header_hash(tx);
  }
  r += tx_prevout_hash(&(tx->hasher), input);
  if (tx->is_decred) {
    uint8_t tree = input->decred_tree & 0xFF;
    hasher_Update(&(tx->hasher), (const uint8_t *)&(tree), 1);
    r++;
  } else {
    r += tx_script_hash(&(tx->hasher), input->script_sig.size, input->script_sig.bytes);
  }
  r += tx_sequence_hash(&(tx->hasher), input);

  tx->have_inputs++;
  tx->size += r;

  return r;
}

uint32_t tx_serialize_extra_data_hash(TxStruct *tx, const uint8_t *data, uint32_t datalen) {
  if (tx->have_inputs < tx->inputs_len) {
    // not all inputs provided
    return 0;
  }
  if (tx->have_outputs < tx->outputs_len) {
    // not all inputs provided
    return 0;
  }
  if (tx->extra_data_received + datalen > tx->extra_data_len) {
    // we are receiving too much data
    return 0;
  }
  hasher_Update(&(tx->hasher), data, datalen);
  tx->extra_data_received += datalen;
  tx->size += datalen;
  return datalen;
}

int compile_output(const CoinInfo *coin, const HDNode *root, TxOutputType *in, TxOutputBinType *out, bool needs_confirm) {
  memzero(out, sizeof(TxOutputBinType));
  out->amount = in->amount;
  out->decred_script_version = in->decred_script_version;
  uint8_t addr_raw[MAX_ADDR_RAW_SIZE];
  size_t addr_raw_len;

  if (in->script_type == OutputScriptType_PAYTOOPRETURN) {
    // only 0 satoshi allowed for OP_RETURN
    if (in->amount != 0) {
      return 0;  // failed to compile output
    }
    if (needs_confirm) {
      if (in->op_return_data.size >= 8 && memcmp(in->op_return_data.bytes, "omni", 4) == 0) {  // OMNI transaction
        // layoutConfirmOmni(in->op_return_data.bytes, in->op_return_data.size);
      } else {
        // layoutConfirmOpReturn(in->op_return_data.bytes, in->op_return_data.size);
      }
      if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
        return -1;  // user aborted
      }
    }
    uint32_t r = 0;
    out->script_pubkey.bytes[0] = 0x6A;
    r++;  // OP_RETURN
    r += op_push(in->op_return_data.size, out->script_pubkey.bytes + r);
    memcpy(out->script_pubkey.bytes + r, in->op_return_data.bytes, in->op_return_data.size);
    r += in->op_return_data.size;
    out->script_pubkey.size = r;
    return r;
  }

  if (in->address_n_count > 0) {
    static CONFIDENTIAL HDNode node;
    InputScriptType input_script_type;

    switch (in->script_type) {
      case OutputScriptType_PAYTOADDRESS:
        input_script_type = InputScriptType_SPENDADDRESS;
        break;
      case OutputScriptType_PAYTOMULTISIG:
        input_script_type = InputScriptType_SPENDMULTISIG;
        break;
      case OutputScriptType_PAYTOWITNESS:
        input_script_type = InputScriptType_SPENDWITNESS;
        break;
      case OutputScriptType_PAYTOP2SHWITNESS:
        input_script_type = InputScriptType_SPENDP2SHWITNESS;
        break;
      default:
        return 0;  // failed to compile output
    }
    memcpy(&node, root, sizeof(HDNode));
    if (hdnode_private_ckd_cached(&node, in->address_n, in->address_n_count,
                                  NULL) == 0) {
      return 0;  // failed to compile output
    }
    hdnode_fill_public_key(&node);
    if (!compute_address(coin, input_script_type, &node, in->has_multisig,
                         &in->multisig, in->address)) {
      return 0;  // failed to compile output
    }
  } else if (!in->has_address) {
    return 0;  // failed to compile output
  }

  addr_raw_len = base58_decode_check(in->address, coin->curve->hasher_base58,
                                     addr_raw, MAX_ADDR_RAW_SIZE);
  size_t prefix_len;
  if (coin->has_address_type  // p2pkh
      && addr_raw_len ==
             20 + (prefix_len = address_prefix_bytes_len(coin->address_type)) &&
      address_check_prefix(addr_raw, coin->address_type)) {
    out->script_pubkey.bytes[0] = 0x76;  // OP_DUP
    out->script_pubkey.bytes[1] = 0xA9;  // OP_HASH_160
    out->script_pubkey.bytes[2] = 0x14;  // pushing 20 bytes
    memcpy(out->script_pubkey.bytes + 3, addr_raw + prefix_len, 20);
    out->script_pubkey.bytes[23] = 0x88;  // OP_EQUALVERIFY
    out->script_pubkey.bytes[24] = 0xAC;  // OP_CHECKSIG
    out->script_pubkey.size = 25;
  } else if (coin->has_address_type_p2sh  // p2sh
             && addr_raw_len == 20 + (prefix_len = address_prefix_bytes_len(
                                          coin->address_type_p2sh)) &&
             address_check_prefix(addr_raw, coin->address_type_p2sh)) {
    out->script_pubkey.bytes[0] = 0xA9;  // OP_HASH_160
    out->script_pubkey.bytes[1] = 0x14;  // pushing 20 bytes
    memcpy(out->script_pubkey.bytes + 2, addr_raw + prefix_len, 20);
    out->script_pubkey.bytes[22] = 0x87;  // OP_EQUAL
    out->script_pubkey.size = 23;
  } else if (coin->cashaddr_prefix &&
             cash_addr_decode(addr_raw, &addr_raw_len, coin->cashaddr_prefix,
                              in->address)) {
    if (addr_raw_len == 21 && addr_raw[0] == (CASHADDR_P2KH | CASHADDR_160)) {
      out->script_pubkey.bytes[0] = 0x76;  // OP_DUP
      out->script_pubkey.bytes[1] = 0xA9;  // OP_HASH_160
      out->script_pubkey.bytes[2] = 0x14;  // pushing 20 bytes
      memcpy(out->script_pubkey.bytes + 3, addr_raw + 1, 20);
      out->script_pubkey.bytes[23] = 0x88;  // OP_EQUALVERIFY
      out->script_pubkey.bytes[24] = 0xAC;  // OP_CHECKSIG
      out->script_pubkey.size = 25;

    } else if (addr_raw_len == 21 &&
               addr_raw[0] == (CASHADDR_P2SH | CASHADDR_160)) {
      out->script_pubkey.bytes[0] = 0xA9;  // OP_HASH_160
      out->script_pubkey.bytes[1] = 0x14;  // pushing 20 bytes
      memcpy(out->script_pubkey.bytes + 2, addr_raw + 1, 20);
      out->script_pubkey.bytes[22] = 0x87;  // OP_EQUAL
      out->script_pubkey.size = 23;
    } else {
      return 0;
    }
  } else if (coin->bech32_prefix) {
    int witver;
    if (!segwit_addr_decode(&witver, addr_raw, &addr_raw_len,
                            coin->bech32_prefix, in->address)) {
      return 0;
    }
    // segwit:
    // push 1 byte version id (opcode OP_0 = 0, OP_i = 80+i)
    // push addr_raw (segwit_addr_decode makes sure addr_raw_len is at most 40)
    out->script_pubkey.bytes[0] = witver == 0 ? 0 : 80 + witver;
    out->script_pubkey.bytes[1] = addr_raw_len;
    memcpy(out->script_pubkey.bytes + 2, addr_raw, addr_raw_len);
    out->script_pubkey.size = addr_raw_len + 2;
  } else {
    return 0;
  }

  if (needs_confirm) {
    layoutConfirmOutput(coin, in);
    if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmOutput, false)) {
      return -1;  // user aborted
    }
  }

  return out->script_pubkey.size;
}