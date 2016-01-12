/* BELT (STB 34.101.31) Hash Function Implementation
 * Copyright (C) 2015  Evgeny Sidorov <luc-lynx@yandex.com>
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

#ifndef BELT_HASH_H
#define BELT_HASH_H

#include <inttypes.h>

#if defined(__cplusplus)
extern "C" {
#endif
    
#define BELT_HASH_SIZE 32
#define BELT_HASH_BLOCK_LEN 32

// describes hash algorithm state
typedef struct
{
    // 128 bit len and 128 bit state s
    uint8_t len_state[BELT_HASH_SIZE];
    // ptr to state inside the len_state array
    uint8_t* state_ptr;
    // ptr to len inside the len_state array
    uint8_t* len_ptr;
    // tmp buffer for blocks len != 256 bits
    uint8_t accumulator[BELT_HASH_BLOCK_LEN];
    // how many bytes of accumulator are in use
    uint32_t acc_occupied;
    // h variable
    uint8_t h[BELT_HASH_BLOCK_LEN];
} belt_hash_state;

void belt_hash_init(belt_hash_state ctx[1]);
void belt_hash(const uint8_t data[], uint64_t len, belt_hash_state ctx[1]);
void belt_end(uint8_t hval[], belt_hash_state ctx[1]);
void belt_calculate(const uint8_t* data, uint64_t len, uint8_t hval[]);
    
#if defined(__cplusplus)
}
#endif

#endif //BELT_HASH_H

