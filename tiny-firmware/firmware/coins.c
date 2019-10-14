
#include "coins.h"
#include "bitcoin.h"
#include <string.h>

const CoinInfo *coinByName(const char *name) {
  if (!name) return 0;
  for (int i = 0; i < COINS_COUNT; i++) {
    if (strcmp(name, coins[i].coin_name) == 0) {
      return &(coins[i]);
    }
  }
  return 0;
}