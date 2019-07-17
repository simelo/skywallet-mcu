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

#ifndef TEMPERATURE_SENSOR
#define TEMPERATURE_SENSOR

#include <inttypes.h>

typedef unsigned short uint16;
typedef uint32_t uint32;

typedef enum rcc_clk_id {
    RCC_GPIOA,
    RCC_GPIOB,
    RCC_GPIOC,
    RCC_GPIOD,
//    RCC_AFIO,
    RCC_ADC1,
    RCC_ADC2,
    RCC_ADC3,
    RCC_USART1,
    RCC_USART2,
    RCC_USART3,
    RCC_TIMER1,
    RCC_TIMER2,
    RCC_TIMER3,
    RCC_TIMER4,
    RCC_SPI1,
    RCC_SPI2,
    RCC_DMA1,
    RCC_PWR,
    RCC_BKP,
    RCC_I2C1,
    RCC_I2C2,
    RCC_CRC,
//    RCC_FLITF,
//    RCC_SRAM,
    RCC_GPIOE,
    RCC_GPIOF,
    RCC_GPIOG,
    RCC_UART4,
    RCC_UART5,
    RCC_TIMER5,
    RCC_TIMER6,
    RCC_TIMER7,
    RCC_TIMER8,
    RCC_FSMC,
    RCC_DAC,
    RCC_DMA2,
    RCC_SDIO,
    RCC_SPI3,
    RCC_TIMER9,
    RCC_TIMER10,
    RCC_TIMER11,
    RCC_TIMER12,
    RCC_TIMER13,
    RCC_TIMER14,
    RCC_USBFS,
    RCC_SYSCFG,
	RCC_SPI4
} rcc_clk_id;

typedef struct adc_reg_map {
    volatile uint32 SR;             ///< Status register
    volatile uint32 CR1;            ///< Control register 1
    volatile uint32 CR2;            ///< Control register 2
    volatile uint32 SMPR1;          ///< Sample time register 1
    volatile uint32 SMPR2;          ///< Sample time register 2
    volatile uint32 JOFR1;          ///< Injected channel data offset register 1
    volatile uint32 JOFR2;          ///< Injected channel data offset register 2
    volatile uint32 JOFR3;          ///< Injected channel data offset register 3
    volatile uint32 JOFR4;          ///< Injected channel data offset register 4
    volatile uint32 HTR;            ///< Watchdog high threshold register
    volatile uint32 LTR;            ///< Watchdog low threshold register
    volatile uint32 SQR1;           ///< Regular sequence register 1
    volatile uint32 SQR2;           ///< Regular sequence register 2
    volatile uint32 SQR3;           ///< Regular sequence register 3
    volatile uint32 JSQR;           ///< Injected sequence register
    volatile uint32 JDR1;           ///< Injected data register 1
    volatile uint32 JDR2;           ///< Injected data register 2
    volatile uint32 JDR3;           ///< Injected data register 3
    volatile uint32 JDR4;           ///< Injected data register 4
    volatile uint32 DR;             ///< Regular data register
} adc_reg_map;

typedef struct adc_dev {
    adc_reg_map *regs; /**< Register map */
    rcc_clk_id clk_id; /**< RCC clock information */
} adc_dev;

#define ADC1_BASE          ((struct adc_reg_map*)0x40012000)
#define ADC_SQR1_L         (0x1F << 20)
#define ADC_CR2_SWSTART    (1U << 22)
#define ADC_SR_EOC         (1UL << 1)
#define ADC_DR_DATA        0xFFFF

uint16 tempRead(void);

#endif