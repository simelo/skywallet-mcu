/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "buttons.h"

struct buttonState button;
bool simulateButtonPress = false;
int buttonPressType;

#if !EMULATOR
uint16_t buttonRead(void) {
	return gpio_port_read(BTN_PORT);
}
#endif

void buttonUpdate()
{
	uint16_t state;
	static uint16_t last_state = BTN_PIN_YES | BTN_PIN_NO;

	state = buttonRead();

	if ((state & BTN_PIN_YES) == 0) {	// Yes button is down
		button.YesDown = ((last_state & BTN_PIN_YES) == 0) ? button.YesDown + (int)(button.YesDown < 2000000000) : 0;
		button.YesUp = false;
	} else {				// Yes button is up
		button.YesDown = 0;
		button.YesUp = (last_state & BTN_PIN_YES) == 0;
	}

	if ((state & BTN_PIN_NO) == 0) {	// No button is down
		button.NoDown = ((last_state & BTN_PIN_NO) == 0) ? button.NoDown + (int)(button.NoDown < 2000000000) : 0;
		button.NoUp = false;
	} else {				// No button is up
		button.NoUp = (last_state & BTN_PIN_NO) == 0;
		button.NoDown = 0;
	}

	#if EMULATOR
		if ( simulateButtonPress ) { /// If a fake button press event is detected, override button state
			if ( buttonPressType == BTN_LEFT ) { /// Press NO
				button.NoDown = 0;
				button.NoUp = true;
			} else if ( buttonPressType == BTN_RIGHT ) { /// Press YES
				button.YesDown = 0;
				button.YesUp = true;
			} else if ( buttonPressType == BTN_LEFT_RIGHT ) { /// Press BOTH
				button.NoDown = 0;
				button.NoUp = true;
				button.YesDown = 0;
				button.YesUp = true;
			}
		}//*/
	#endif

	last_state = state;
}
