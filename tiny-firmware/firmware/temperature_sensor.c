/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include "temperature_sensor.h"

#ifdef EMULATOR
uint16 tempRead(void) {
  return 0;
}
#else
uint16 tempRead(void) {
  const uint8 channel = 16;

  const adc_dev ADC1 = {
    .regs   = ADC1_BASE,
    .clk_id = RCC_ADC1
  };

  adc_reg_map *regs = ADC1_BASE;

  uint32 tmp = regs->SQR1;
  tmp &= ~ADC_SQR1_L;
  regs->SQR1 = tmp;

  regs->SQR3 = channel;
  regs->CR2 |= ADC_CR2_SWSTART;

  while (!(regs->SR & ADC_SR_EOC));

  return (uint16)(regs->DR & ADC_DR_DATA);
}
#endif