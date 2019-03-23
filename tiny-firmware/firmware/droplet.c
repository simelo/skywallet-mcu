
#include "droplet.h"
#include <stdio.h>
#include <inttypes.h>

size_t digitsOf(uint64_t n) {

  size_t cant = 0;

  do {
    n = n / 10;
    ++cant;
  } while( n > 0 );

  return cant;

}

char *sprint_coins(uint64_t coins, int precision_exp, size_t sz, char *msg) {
  char *ptr = msg + sz;
  *ptr = 0;
  ptr--;

  uint64_t div, mod;

  div = coins / 1000000;
  mod = coins % 1000000;

  /// Skip least significant decimal digits
  while ( mod && mod % 10 == 0 ) {
    mod = mod / 10;
    --precision_exp;
  }

  /// Check if the length of the coins to display, fit into it
  if ( digitsOf(div) + digitsOf(mod) + (( mod != 0 ) ? 1 : 0) > sz ) {
    return NULL;
  }

  /// Trivial case!!
  if ( div == 0 && mod == 0 ) {
    *ptr = '0';
    return ptr;
  }

  /// Print decimal digits
  if ( mod != 0 ) {
    for ( ;precision_exp > 0; ptr--, precision_exp--) {
      *ptr = '0' + (mod % 10);
      mod = mod / 10;
    }
    *ptr = '.';
    ptr--;
  }

  // Print integer part
  do {
    *ptr = '0' + (div % 10);
    div = div / 10;
    ptr--;
  } while( div > 0 );

  return ++ptr;

}
