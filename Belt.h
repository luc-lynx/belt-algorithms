/* BELT (STB 34.101.31) Encryption Algorithm Implementation
 * Copyright (C) 2013  Evgeny Sidorov <luc-lynx@yandex.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef BELT_H
#define BELT_H

#include <inttypes.h>

#define BELT_KS 32
#define BELT_BLOCK_LEN 16

#if defined(__cplusplus)
extern "C" 
{
#endif

void belt_init(uint8_t* k, int kLen, uint8_t* ks);
void belt_encrypt(uint8_t* ks, uint8_t* inBlock, uint8_t* outBlock);
void belt_decrypt(uint8_t* ks, uint8_t* inBlock, uint8_t* outBlock);

#if defined(__cplusplus)
}
#endif

#endif

