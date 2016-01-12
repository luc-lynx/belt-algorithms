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

#include <string.h>     /* for memcpy() etc.        */

#include "BeltHash.h"
#include "Belt.h"

static void sigma1_xor(uint8_t* x, uint8_t* h, uint8_t* state)
{
    uint8_t u3u4[BELT_BLOCK_LEN];
    uint8_t tmp[BELT_BLOCK_LEN];
    
    ((uint64_t*)u3u4)[0] = ((uint64_t*)h)[0] ^ ((uint64_t*)h)[2];
    ((uint64_t*)u3u4)[1] = ((uint64_t*)h)[1] ^ ((uint64_t*)h)[3];
    
    belt_encrypt(x, u3u4, tmp);
    
    ((uint64_t*)state)[0] ^= (((uint64_t*)tmp)[0] ^ ((uint64_t*)u3u4)[0]);
    ((uint64_t*)state)[1] ^= (((uint64_t*)tmp)[1] ^ ((uint64_t*)u3u4)[1]);
}

static void sigma1(uint8_t* u12, uint8_t* u34, uint8_t* result)
{
    uint8_t u3u4[BELT_BLOCK_LEN];
    
    ((uint64_t*)u3u4)[0] = ((uint64_t*)u34)[0] ^ ((uint64_t*)u34)[2];
    ((uint64_t*)u3u4)[1] = ((uint64_t*)u34)[1] ^ ((uint64_t*)u34)[3];
    
    belt_encrypt(u12, u3u4, result);
    
    ((uint64_t*)result)[0] ^= ((uint64_t*)u3u4)[0];
    ((uint64_t*)result)[1] ^= ((uint64_t*)u3u4)[1];
}

// it's safe to put h here into result
// x = u1 || u2, h = u3 || u4
// len(x) = 256 bit, len(h) = 256 bit
static void sigma2(uint8_t* x, uint8_t* h, uint8_t* result)
{
    uint8_t teta[BELT_KS];
    uint64_t h0 = ((uint64_t*)h)[0];
    uint64_t h1 = ((uint64_t*)h)[1];
    
    // teta1 = sigma1(u) || u4
    sigma1(x, h, teta);
    ((uint64_t*)teta)[2] = ((uint64_t*)h)[2];
    ((uint64_t*)teta)[3] = ((uint64_t*)h)[3];
    
    // F_{teta1}(u1) xor u1
    belt_encrypt(teta, x, result);
    
    ((uint64_t*)result)[0] ^= ((uint64_t*)x)[0];
    ((uint64_t*)result)[1] ^= ((uint64_t*)x)[1];
    
    // (sigma1(u) xor 0xff..ff) || u3
    // invert first part of teta1
    ((uint64_t*)teta)[0] ^= 0xffffffffffffffffull;
    ((uint64_t*)teta)[1] ^= 0xffffffffffffffffull;
    
    // if result == h at this moment original h[0] and h[1] are lost
    ((uint64_t*)teta)[2] = h0;
    ((uint64_t*)teta)[3] = h1;

    belt_encrypt(teta, x + BELT_BLOCK_LEN, result + BELT_BLOCK_LEN);

    ((uint64_t*)result)[2] ^= ((uint64_t*)x)[2];
    ((uint64_t*)result)[3] ^= ((uint64_t*)x)[3];
}

static void iteration(uint8_t* x, uint8_t* h, uint8_t* s)
{
    // update state: s <- s xor sigma1(x_i || h)
    sigma1_xor(x, h, s);
    // update h: h <- sigma2(x_i || h)
    sigma2(x, h, h);
}

static void finalize(belt_hash_state ctx[1], uint8_t* result)
{
    sigma2(ctx->len_state, ctx->h, result);
}

static void increment_len_block(belt_hash_state ctx[1])
{
    ((uint64_t*) ctx->len_ptr)[0] += (BELT_HASH_BLOCK_LEN << 3);
    if(((uint64_t*) ctx->len_ptr)[0] < (BELT_HASH_BLOCK_LEN << 3)){
        ((uint64_t*) ctx->len_ptr)[1] += 1;
    }
}

static void increment_len_bytes(belt_hash_state ctx[1], uint64_t bytes)
{
    ((uint64_t*) ctx->len_ptr)[0] += (bytes << 3);
    if(((uint64_t*) ctx->len_ptr)[0] < (bytes << 3)){
        ((uint64_t*) ctx->len_ptr)[1] += 1;
    }
}

void belt_hash_init(belt_hash_state ctx[1])
{
    ctx->len_ptr = (uint8_t*)ctx->len_state;
    ctx->state_ptr = (uint8_t*)ctx->len_state + 16;
    ((uint64_t*)ctx->len_state)[0] = 0;
    ((uint64_t*)ctx->len_state)[1] = 0;
    ((uint64_t*)ctx->len_state)[2] = 0;
    ((uint64_t*)ctx->len_state)[3] = 0;
    ((uint64_t*)ctx->accumulator)[0] = 0;
    ((uint64_t*)ctx->accumulator)[1] = 0;
    ((uint64_t*)ctx->accumulator)[2] = 0;
    ((uint64_t*)ctx->accumulator)[3] = 0;
    ((uint64_t*)ctx->h)[0] = 0x3bf5080ac8ba94b1ull; //0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0xF5, 0x3B,
    ((uint64_t*)ctx->h)[1] = 0xe45d4a588e006d36ull; //0x36, 0x6D, 0x00, 0x8E, 0x58, 0x4A, 0x5D, 0xE4,
    ((uint64_t*)ctx->h)[2] = 0xacc7b61b9dfa0485ull; //0x85, 0x04, 0xFA, 0x9D, 0x1B, 0xB6, 0xC7, 0xAC,
    ((uint64_t*)ctx->h)[3] = 0x0dcefd02c2722e25ull; //0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D
    ctx->acc_occupied = 0;
}

void belt_hash(const uint8_t* data, uint64_t len, belt_hash_state ctx[1])
{
    if(ctx->acc_occupied > 0){
        if(ctx->acc_occupied + len < BELT_HASH_BLOCK_LEN){
            memcpy(ctx->accumulator + ctx->acc_occupied, data, len);
            ctx->acc_occupied += len;
            return;
        }
        else
        {
            memcpy(ctx->accumulator + ctx->acc_occupied, data, BELT_HASH_BLOCK_LEN - ctx->acc_occupied);
            data += (BELT_HASH_BLOCK_LEN - ctx->acc_occupied);
            len -= (BELT_HASH_BLOCK_LEN - ctx->acc_occupied);
            
            increment_len_block(ctx);
            iteration(ctx->accumulator, ctx->h, ctx->state_ptr);
            
            ctx->acc_occupied = 0;
        }
    }
    
    ctx->acc_occupied = len & (BELT_HASH_BLOCK_LEN - 1);
    
    while (len > ctx->acc_occupied) {
        increment_len_block(ctx);
        iteration((uint8_t*)data, ctx->h, ctx->state_ptr);
        data += BELT_HASH_BLOCK_LEN;
        len -= BELT_HASH_BLOCK_LEN;
    }
    
    if(ctx->acc_occupied > 0)
        memcpy(ctx->accumulator, data, ctx->acc_occupied);
}

void belt_end(uint8_t hval[], belt_hash_state ctx[1])
{
    uint32_t i;
    if(ctx->acc_occupied > 0)
    {
        for (i = 0; i < BELT_HASH_BLOCK_LEN - ctx->acc_occupied; i += 1) {
            ctx->accumulator[ctx->acc_occupied + i] = 0;
        }
        iteration(ctx->accumulator, ctx->h, ctx->state_ptr);
        increment_len_bytes(ctx, ctx->acc_occupied);
    }
    finalize(ctx, hval);
}

void belt_calculate(const uint8_t* data, uint64_t len, uint8_t hval[])
{
    belt_hash_state ctx;
    belt_hash_init(&ctx);
    
    ctx.acc_occupied = len & (BELT_HASH_BLOCK_LEN - 1);
    while(len > ctx.acc_occupied)
    {
        increment_len_block(&ctx);
        iteration((uint8_t*)data, ctx.h, ctx.state_ptr);
        data += BELT_HASH_BLOCK_LEN;
        len -= BELT_HASH_BLOCK_LEN;
    }
    
    if(ctx.acc_occupied > 0)
    {
        memcpy(ctx.accumulator, data, ctx.acc_occupied);
        iteration(ctx.accumulator, ctx.h, ctx.state_ptr);
        increment_len_bytes(&ctx, ctx.acc_occupied);
    }
    
    finalize(&ctx, hval);
}

