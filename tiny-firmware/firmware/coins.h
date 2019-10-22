
#ifndef __COINS_H__
#define __COINS_H__

#include <stdint.h>
#include "bip32.h"

typedef struct _CoinInfo {
  const char *coin_name;
  const char *coin_shortcut;
  uint64_t maxfee_kb;
  const char *signed_message_header;
  bool has_address_type;
  bool has_address_type_p2sh;
  bool has_segwit;
  bool has_fork_id;
  bool force_bip143;
  bool decred;
  // address types > 0xFF represent a two-byte prefix in big-endian order
  uint32_t address_type;
  uint32_t address_type_p2sh;
  uint32_t xpub_magic;
  uint32_t xpub_magic_segwit_p2sh;
  uint32_t xpub_magic_segwit_native;
  uint32_t fork_id;
  const char *bech32_prefix;
  const char *cashaddr_prefix;
  uint32_t coin_type;
  bool negative_fee;
  const char *curve_name;
  const curve_info *curve;
} CoinInfo;

const CoinInfo *coinByName(const char *name);
const CoinInfo *coinByAddressType(uint32_t address_type);

#endif
