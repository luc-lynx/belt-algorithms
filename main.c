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

#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include "BeltHash.h"

const uint8_t x1[] = {
    0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B,
    0x36, 0x6D, 0x00, 0x8E, 0x58
};

const uint8_t r1[] = {
    0xAB, 0xEF, 0x97, 0x25, 0xD4, 0xC5, 0xA8, 0x35,
    0x97, 0xA3, 0x67, 0xD1, 0x44, 0x94, 0xCC, 0x25,
    0x42, 0xF2, 0x0F, 0x65, 0x9D, 0xDF, 0xEC, 0xC9,
    0x61, 0xA3, 0xEC, 0x55, 0x0C, 0xBA, 0x8C, 0x75
};

const uint8_t x2[] = {
    0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B,
    0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
    0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC,
    0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D
};

const uint8_t r2[] = {
    0x74, 0x9E, 0x4C, 0x36, 0x53, 0xAE, 0xCE, 0x5E,
    0x48, 0xDB, 0x47, 0x61, 0x22, 0x77, 0x42, 0xEB,
    0x6D, 0xBE, 0x13, 0xF4, 0xA8, 0x0F, 0x7B, 0xEF,
    0xF1, 0xA9, 0xCF, 0x8D, 0x10, 0xEE, 0x77, 0x86
};

const uint8_t x3[] = {
    0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B,
    0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
    0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC,
    0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D,
    0x5B, 0xE3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81,
    0xFE, 0x67, 0x86, 0xAD, 0x71, 0x6B, 0x89, 0x0B
};

const uint8_t r3[] = {
    0x9D, 0x02, 0xEE, 0x44, 0x6F, 0xB6, 0xA2, 0x9F,
    0xE5, 0xC9, 0x82, 0xD4, 0xB1, 0x3A, 0xF9, 0xD3,
    0xE9, 0x08, 0x61, 0xBC, 0x4C, 0xEF, 0x27, 0xCF,
    0x30, 0x6B, 0xFB, 0x0B, 0x17, 0x4A, 0x15, 0x4A
};

uint32_t test_belt_calculate(const uint8_t* enter, uint32_t enter_len, const uint8_t* result, uint32_t result_len){
    uint8_t belt_result[BELT_HASH_SIZE];
    if(result_len != BELT_HASH_BLOCK_LEN)
        return 0;
    belt_calculate(enter, enter_len, belt_result);
    
    return (memcmp(belt_result, result, BELT_HASH_SIZE) == 0);
}

uint32_t test_belt_hash(const uint8_t* enter, uint32_t enter_len, const uint8_t* result, uint32_t result_len){
    belt_hash_state state;
    uint8_t belt_result[BELT_HASH_SIZE];
    
    if(result_len != BELT_HASH_BLOCK_LEN)
        return 0;
    
    belt_hash_init(&state);
    belt_hash(enter, enter_len, &state);
    belt_end(belt_result, &state);
    
    return (memcmp(belt_result, result, BELT_HASH_SIZE) == 0);
}

uint32_t test_belt_hash_bytes(const uint8_t* enter, uint32_t enter_len, const uint8_t* result, uint32_t result_len){
    belt_hash_state state;
    uint8_t belt_result[BELT_HASH_SIZE];
    uint32_t i = 0;
    
    if(result_len != BELT_HASH_BLOCK_LEN)
        return 0;
    
    belt_hash_init(&state);
    
    for(i = 0; i < enter_len; i += 1)
    {
        belt_hash(enter + i, 1, &state);
    }
    
    belt_end(belt_result, &state);
    
    return (memcmp(belt_result, result, BELT_HASH_SIZE) == 0);
}

int main(int argc, const char * argv[]) {
    printf("Testing whole hash calculation:\n");
    
    printf("\tTest X1...");
    if(test_belt_calculate(x1, sizeof(x1), r1, sizeof(r1))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");
    
    printf("\tTest X2...");
    if(test_belt_calculate(x2, sizeof(x2), r2, sizeof(r2))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");
    
    printf("\tTest X3...");
    if(test_belt_calculate(x3, sizeof(x3), r3, sizeof(r3))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");
    
    printf("Testing BeltHash separate functions:\n");
    
    printf("\tTest X1...");
    if(test_belt_hash(x1, sizeof(x1), r1, sizeof(r1))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");
    
    printf("\tTest X2...");
    if(test_belt_hash(x2, sizeof(x2), r2, sizeof(r2))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");
    
    printf("\tTest X3...");
    if(test_belt_hash(x3, sizeof(x3), r3, sizeof(r3))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");
    
    printf("Testing BeltHash - passing data byte by byte:\n");
    
    printf("\tTest X1...");
    if(test_belt_hash_bytes(x1, sizeof(x1), r1, sizeof(r1))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");
    
    printf("\tTest X2...");
    if(test_belt_hash_bytes(x2, sizeof(x2), r2, sizeof(r2))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");
    
    printf("\tTest X3...");
    if(test_belt_hash_bytes(x3, sizeof(x3), r3, sizeof(r3))){
        printf("OK");
    } else {
        printf("FAIL");
    }
    printf("\n");
}

