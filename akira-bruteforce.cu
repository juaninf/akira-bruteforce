#include <cuda_runtime.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fstream>
#include <unistd.h>
//stat
#include <sys/types.h>
#include <sys/stat.h>
//mmap
#include <sys/mman.h>
#include <fcntl.h>
#include "json.hpp"
#include "test-ts.h"
#include "akira-bruteforce.h"
#include "chacha8.h"

//by design, max matches is 127
#define MAX_MATCHES 32

using json = nlohmann::json;

int gpuIndex = 0;

#define SHA256_DIGEST_SIZE 32

// --- SHA-256 Device Implementation ---

// Rotate right.
__device__ __forceinline__ uint32_t rotr(uint32_t x, uint32_t n)
{
    //return (x >> n) | (x << (32 - n));
        return __funnelshift_r(x, x, n );

}


#define SHR(x, n) ((x) >> (n))
#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22))
#define Sigma1(x) (rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25))
#define sigma0(x) (rotr(x, 7) ^ rotr(x, 18) ^ SHR(x, 3))
#define sigma1(x) (rotr(x, 17) ^ rotr(x, 19) ^ SHR(x, 10))

// Process one 64-byte block.
__device__ __forceinline__ void sha256_transform(const uint8_t *data, uint32_t state[8], const uint32_t *k)
{
    uint32_t w[64];
#pragma unroll
    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++)
    {
        w[i] = sigma1(w[i - 2]) + w[i - 7] + sigma0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int i = 0; i < 64; i++)
    {
        uint32_t T1 = h + Sigma1(e) + Ch(e, f, g) + k[i] + w[i];
        uint32_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

// For a fixed 19-byte input, the padded message is exactly 64 bytes.
// Padding: message (19 bytes) || 0x80 || (zeros up to byte 56) || [0x0000000000000098]
// (19*8 = 152, or 0x98)
__device__ void sha256_hash_19(const uint8_t *msg, uint8_t *digest, const uint32_t *k)
{
    uint32_t state[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19};

    
    uint8_t block[64];

#pragma unroll
    for (int i = 0; i < 19; i++)
        block[i] = msg[i];
    block[19] = 0x80;
#pragma unroll
    for (int i = 20; i < 56; i++)
        block[i] = 0;
    // Append message length in bits: 152 = 0x0000000000000098 (big-endian)
    block[56] = 0;
    block[57] = 0;
    block[58] = 0;
    block[59] = 0;
    block[60] = 0;
    block[61] = 0;
    block[62] = 0;
    block[63] = 152;

    sha256_transform(block, state, k);

#pragma unroll
    for (int i = 0; i < 8; i++)
    {
        digest[i * 4] = (state[i] >> 24) & 0xff;
        digest[i * 4 + 1] = (state[i] >> 16) & 0xff;
        digest[i * 4 + 2] = (state[i] >> 8) & 0xff;
        digest[i * 4 + 3] = state[i] & 0xff;
    }
}

// For a fixed 68-byte input, the padded message consists of 2 blocks.
// Block 1: first 64 bytes of the input.
// Block 2: remaining 4 bytes || 0x80 || zeros until byte 56 || [bit length = 544 bits]
__device__ void sha256_hash_68(const uint8_t * msg, uint8_t *digest, const uint32_t *  k)
{
    uint32_t state[8] = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19};

    uint8_t block2[64];

    // Block 1: copy first 64 bytes.

    //uint8_t block[64];
#pragma unroll	    
    for (int i = 0; i < 64; i++)
	    block2[i] = msg[i];
    sha256_transform(block2, state, k);
    

    // Block 2:
    // First 4 bytes: remainder of message.
#pragma unroll
    for (int i = 0; i < 4; i++)
        block2[i] = msg[64 + i];
    block2[4] = 0x80;
#pragma unroll
    for (int i = 5; i < 56; i++)
        block2[i] = 0;
    // Append message length in bits: 68*8 = 544 = 0x0000000000000220 (big-endian)
    block2[56] = 0;
    block2[57] = 0;
    block2[58] = 0;
    block2[59] = 0;
    block2[60] = 0;
    block2[61] = 0;
    block2[62] = 0x02;
    block2[63] = 0x20;

    sha256_transform(block2, state, k);

#pragma unroll
    for (int i = 0; i < 8; i++)
    {
        digest[i * 4] = (state[i] >> 24) & 0xff;
        digest[i * 4 + 1] = (state[i] >> 16) & 0xff;
        digest[i * 4 + 2] = (state[i] >> 8) & 0xff;
        digest[i * 4 + 3] = state[i] & 0xff;
    }
}

// Minimal AES-256 context and helper functions.
typedef struct
{
    uint32_t rk[60]; // 60 words for 14 rounds + initial key
} aes256_ctx;

__device__ __forceinline__ uint32_t SubWord(uint32_t word, const uint8_t *sbox)
{
    return ((uint32_t)sbox[(word >> 24)] << 24) |
           ((uint32_t)sbox[(word >> 16) & 0xff] << 16) |
           ((uint32_t)sbox[(word >> 8) & 0xff] << 8) |
           ((uint32_t)sbox[word & 0xff]);
}

__device__ inline uint32_t RotWord(uint32_t word)
{
    //return (word << 8) | (word >> 24);
    return __funnelshift_l(word, word, 8);

}

// Key expansion for AES-256.
__device__ void aes256_set_encrypt_key(const uint8_t userKey[32], aes256_ctx *ctx, const uint8_t *sbox, const uint32_t *Rcon)
{
    int i = 0;
    // Copy the 256-bit key into the first 8 words.
    for (i = 0; i < 8; i++)
    {
        ctx->rk[i] = ((uint32_t)userKey[4 * i] << 24) |
                     ((uint32_t)userKey[4 * i + 1] << 16) |
                     ((uint32_t)userKey[4 * i + 2] << 8) |
                     ((uint32_t)userKey[4 * i + 3]);
    }
    int rcon_i = 0;
  
    for (i = 8; i < 60; i++)
    {
	uint32_t temp = ctx->rk[i - 1];
        if ((i % 8) == 0)
        {
            temp = SubWord(RotWord(temp), sbox) ^ Rcon[rcon_i++];
        }
        else if ((i % 8) == 4)
        {
            temp = SubWord(temp, sbox);
        }
        ctx->rk[i] = ctx->rk[i - 8] ^ temp;
    }
}


// AES block encryption for a single 16-byte block.
__device__ void aes256_encrypt(const aes256_ctx *ctx, const uint8_t in[16], uint8_t out[16], const uint8_t *sbox, const uint8_t *xtime)
{
    uint8_t state[16];
    // Copy input into state.
    for (int i = 0; i < 16; i++)
    {
        state[i] = in[i];
    }
    // Initial AddRoundKey.
    for (int i = 0; i < 4; i++)
    {
        uint32_t rk = ctx->rk[i];
        state[4 * i + 0] ^= (uint8_t)(rk >> 24);
        state[4 * i + 1] ^= (uint8_t)(rk >> 16);
        state[4 * i + 2] ^= (uint8_t)(rk >> 8);
        state[4 * i + 3] ^= (uint8_t)(rk);
    }
    // Main rounds.
    for (int round = 1; round < 14; round++)
    {
        // SubBytes.
        for (int i = 0; i < 16; i++)
            state[i] = sbox[state[i]];
        // ShiftRows.
        uint8_t tmp[16];
        tmp[0] = state[0];
        tmp[1] = state[5];
        tmp[2] = state[10];
        tmp[3] = state[15];

        tmp[4] = state[4];
        tmp[5] = state[9];
        tmp[6] = state[14];
        tmp[7] = state[3];

        tmp[8] = state[8];
        tmp[9] = state[13];
        tmp[10] = state[2];
        tmp[11] = state[7];

        tmp[12] = state[12];
        tmp[13] = state[1];
        tmp[14] = state[6];
        tmp[15] = state[11];

        // MixColumns.
        for (int i = 0; i < 4; i++)
        {
            int col = 4 * i;
            uint8_t a0 = tmp[col + 0], a1 = tmp[col + 1],
                    a2 = tmp[col + 2], a3 = tmp[col + 3];
            uint8_t r0 = xtime[a0] ^ (a1 ^ xtime[a1]) ^ a2 ^ a3;
            uint8_t r1 = a0 ^ xtime[a1] ^ (a2 ^ xtime[a2]) ^ a3;
            uint8_t r2 = a0 ^ a1 ^ xtime[a2] ^ (a3 ^ xtime[a3]);
            uint8_t r3 = (a0 ^ xtime[a0]) ^ a1 ^ a2 ^ xtime[a3];
            tmp[col + 0] = r0;
            tmp[col + 1] = r1;
            tmp[col + 2] = r2;
            tmp[col + 3] = r3;
        }
        // Copy back to state.
        for (int i = 0; i < 16; i++)
            state[i] = tmp[i];
        // AddRoundKey.
        for (int i = 0; i < 4; i++)
        {
            uint32_t rk = ctx->rk[round * 4 + i];
            state[4 * i + 0] ^= (uint8_t)(rk >> 24);
            state[4 * i + 1] ^= (uint8_t)(rk >> 16);
            state[4 * i + 2] ^= (uint8_t)(rk >> 8);
            state[4 * i + 3] ^= (uint8_t)(rk);
        }
    }
    // Final round (no MixColumns).
    // SubBytes.
    for (int i = 0; i < 16; i++)
        state[i] = sbox[state[i]];
    // ShiftRows.
    uint8_t tmp[16];
    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];

    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];

    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];
    // Final AddRoundKey.
    for (int i = 0; i < 4; i++)
    {
        uint32_t rk = ctx->rk[14 * 4 + i];
        tmp[4 * i + 0] ^= (uint8_t)(rk >> 24);
        tmp[4 * i + 1] ^= (uint8_t)(rk >> 16);
        tmp[4 * i + 2] ^= (uint8_t)(rk >> 8);
        tmp[4 * i + 3] ^= (uint8_t)(rk);
    }
    // Write result.
    for (int i = 0; i < 16; i++)
        out[i] = tmp[i];
}

// kcipher2 state structure.
typedef struct
{
    unsigned int A[5];
    unsigned int B[11];
    unsigned int L1, R1, L2, R2;
} kcipher2_state;

//---------------------------------------------------------------------------
// Device functions for kcipher2
//---------------------------------------------------------------------------

__device__ __forceinline__ unsigned int nlf(unsigned int a, unsigned int b, unsigned int c, unsigned int d)
{
    return (a + b) ^ c ^ d;
}

__device__ __forceinline__ unsigned char gf_multiply_by_2(unsigned char t)
{
    // return gf2_table[t];
    unsigned int lq = t << 1;
    if (lq & 0x100)
        lq ^= 0x011B;
    return ((unsigned char)lq) ^ 0xFF;
}

__device__ __forceinline__ unsigned char gf_multiply_by_3(unsigned char t)
{
    //    return gf3_table[t];
    unsigned int lq = (t << 1) ^ t;
    if (lq & 0x100)
        lq ^= 0x011B;
    return ((unsigned char)lq) ^ 0xFF;
}

__device__ unsigned int sub_k2(unsigned int in)
{
    unsigned char w0 = in & 0xFF;
    unsigned char w1 = (in >> 8) & 0xFF;
    unsigned char w2 = (in >> 16) & 0xFF;
    unsigned char w3 = (in >> 24) & 0xFF;

    unsigned char t0 = d_s_box[w0];
    unsigned char t1 = d_s_box[w1];
    unsigned char t2 = d_s_box[w2];
    unsigned char t3 = d_s_box[w3];

    unsigned char q0 = gf_multiply_by_2(t0) ^ gf_multiply_by_3(t1) ^ t2 ^ t3;
    unsigned char q1 = t0 ^ gf_multiply_by_2(t1) ^ gf_multiply_by_3(t2) ^ t3;
    unsigned char q2 = t0 ^ t1 ^ gf_multiply_by_2(t2) ^ gf_multiply_by_3(t3);
    unsigned char q3 = gf_multiply_by_3(t0) ^ t1 ^ t2 ^ gf_multiply_by_2(t3);

    return ((unsigned int)q3 << 24) | ((unsigned int)q2 << 16) | ((unsigned int)q1 << 8) | q0;
}

__device__ void setup_state_values(const unsigned int *key, const unsigned int *iv, kcipher2_state *state)
{
    unsigned int IK[12];
    IK[0] = key[0];
    IK[1] = key[1];
    IK[2] = key[2];
    IK[3] = key[3];

    IK[4] = IK[0] ^ sub_k2((IK[3] << 8) ^ (IK[3] >> 24)) ^ 0x01000000;
    IK[5] = IK[1] ^ IK[4];
    IK[6] = IK[2] ^ IK[5];
    IK[7] = IK[3] ^ IK[6];
    IK[8] = IK[4] ^ sub_k2((IK[7] << 8) ^ (IK[7] >> 24)) ^ 0x02000000;

    IK[9] = IK[5] ^ IK[8];
    IK[10] = IK[6] ^ IK[9];
    IK[11] = IK[7] ^ IK[10];

    state->A[0] = IK[4];
    state->A[1] = IK[3];
    state->A[2] = IK[2];
    state->A[3] = IK[1];
    state->A[4] = IK[0];

    state->B[0] = IK[10];
    state->B[1] = IK[11];
    state->B[2] = iv[0];
    state->B[3] = iv[1];
    state->B[4] = IK[8];
    state->B[5] = IK[9];
    state->B[6] = iv[2];
    state->B[7] = iv[3];
    state->B[8] = IK[7];
    state->B[9] = IK[5];
    state->B[10] = IK[6];

    state->L1 = state->R1 = state->L2 = state->R2 = 0x00000000;
}

__device__ void next_INIT(kcipher2_state *state)
{
    unsigned int temp2;
    unsigned int nL1 = sub_k2(state->R2 + state->B[4]);
    unsigned int nR1 = sub_k2(state->L2 + state->B[9]);
    unsigned int nL2 = sub_k2(state->L1);
    unsigned int nR2 = sub_k2(state->R1);

    unsigned int nA[5];
    nA[0] = state->A[1];
    nA[1] = state->A[2];
    nA[2] = state->A[3];
    nA[3] = state->A[4];

    unsigned int nB[11];
    nB[0] = state->B[1];
    nB[1] = state->B[2];
    nB[2] = state->B[3];
    nB[3] = state->B[4];
    nB[4] = state->B[5];
    nB[5] = state->B[6];
    nB[6] = state->B[7];
    nB[7] = state->B[8];
    nB[8] = state->B[9];
    nB[9] = state->B[10];

    unsigned int temp1 = (state->A[0] << 8) ^ d_amul0[(state->A[0] >> 24) & 0xFF];
    nA[4] = temp1 ^ state->A[3];
    nA[4] ^= nlf(state->B[0], state->R2, state->R1, state->A[4]);

    if (state->A[2] & 0x40000000)
        temp1 = (state->B[0] << 8) ^ d_amul1[(state->B[0] >> 24) & 0xFF];
    else
        temp1 = (state->B[0] << 8) ^ d_amul2[(state->B[0] >> 24) & 0xFF];

    // branchless version (not faster)
    //  unsigned int mask = -(unsigned int)(!!(state->A[2] & 0x40000000));
    //  unsigned int candidate1 = (state->B[0] << 8) ^ d_amul1[(state->B[0] >> 24) & 0xFF];
    //  unsigned int candidate2 = (state->B[0] << 8) ^ d_amul2[(state->B[0] >> 24) & 0xFF];
    //  temp1 = candidate2 ^ ((candidate1 ^ candidate2) & mask);

    if (state->A[2] & 0x80000000)
        temp2 = (state->B[8] << 8) ^ d_amul3[(state->B[8] >> 24) & 0xFF];
    else
        temp2 = state->B[8];

    // branchless version (not faster)
    //     unsigned int mask2 = -(unsigned int)(!!(state->A[2] & 0x80000000));
    // unsigned int candidate3 = (state->B[8] << 8) ^ d_amul3[(state->B[8] >> 24) & 0xFF];
    // unsigned int candidate4 = state->B[8];
    // temp2 = candidate4 ^ ((candidate3 ^ candidate4) & mask2);

    nB[10] = temp1 ^ state->B[1] ^ state->B[6] ^ temp2;
    nB[10] ^= nlf(state->B[10], state->L2, state->L1, state->A[0]);

    state->A[0] = nA[0];
    state->A[1] = nA[1];
    state->A[2] = nA[2];
    state->A[3] = nA[3];
    state->A[4] = nA[4];

    state->B[0] = nB[0];
    state->B[1] = nB[1];
    state->B[2] = nB[2];
    state->B[3] = nB[3];
    state->B[4] = nB[4];
    state->B[5] = nB[5];
    state->B[6] = nB[6];
    state->B[7] = nB[7];
    state->B[8] = nB[8];
    state->B[9] = nB[9];
    state->B[10] = nB[10];

    state->L1 = nL1;
    state->R1 = nR1;
    state->L2 = nL2;
    state->R2 = nR2;
}

__device__ unsigned int sub_k2_shared(unsigned int in, const unsigned char *gf2_table, 
        const unsigned char *gf3_table,
        const unsigned char *d_s_box)
{
    unsigned char w0 = in & 0xFF;
    unsigned char w1 = (in >> 8) & 0xFF;
    unsigned char w2 = (in >> 16) & 0xFF;
    unsigned char w3 = (in >> 24) & 0xFF;

    unsigned char t0 = d_s_box[w0];
    unsigned char t1 = d_s_box[w1];
    unsigned char t2 = d_s_box[w2];
    unsigned char t3 = d_s_box[w3];

    unsigned char q0 = gf2_table[t0] ^ gf3_table[t1] ^ t2 ^ t3;
    unsigned char q1 = t0 ^ gf2_table[t1] ^ gf3_table[t2] ^ t3;
    unsigned char q2 = t0 ^ t1 ^ gf2_table[t2] ^ gf3_table[t3];
    unsigned char q3 = gf3_table[t0] ^ t1 ^ t2 ^ gf2_table[t3];

    return ((unsigned int)q3 << 24) | ((unsigned int)q2 << 16) | ((unsigned int)q1 << 8) | q0;
}


__device__ void setup_state_values_shared(const unsigned int *key, const unsigned int *iv, kcipher2_state *state, 
    const unsigned char *gf2_table, 
    const unsigned char *gf3_table,
    const unsigned char *d_s_box)
{
    unsigned int IK[12];
    IK[0] = key[0];
    IK[1] = key[1];
    IK[2] = key[2];
    IK[3] = key[3];

    IK[4] = IK[0] ^ sub_k2_shared((IK[3] << 8) ^ (IK[3] >> 24), gf2_table, gf3_table, d_s_box) ^ 0x01000000;
    IK[5] = IK[1] ^ IK[4];
    IK[6] = IK[2] ^ IK[5];
    IK[7] = IK[3] ^ IK[6];
    IK[8] = IK[4] ^ sub_k2_shared((IK[7] << 8) ^ (IK[7] >> 24), gf2_table, gf3_table, d_s_box) ^ 0x02000000;

    IK[9] = IK[5] ^ IK[8];
    IK[10] = IK[6] ^ IK[9];
    IK[11] = IK[7] ^ IK[10];

    state->A[0] = IK[4];
    state->A[1] = IK[3];
    state->A[2] = IK[2];
    state->A[3] = IK[1];
    state->A[4] = IK[0];

    state->B[0] = IK[10];
    state->B[1] = IK[11];
    state->B[2] = iv[0];
    state->B[3] = iv[1];
    state->B[4] = IK[8];
    state->B[5] = IK[9];
    state->B[6] = iv[2];
    state->B[7] = iv[3];
    state->B[8] = IK[7];
    state->B[9] = IK[5];
    state->B[10] = IK[6];

    state->L1 = state->R1 = state->L2 = state->R2 = 0x00000000;
}



__device__ void next_INIT_shared(kcipher2_state *state, 
    const unsigned char *gf2_table, 
    const unsigned char *gf3_table,
    const unsigned char *d_s_box,
    const unsigned int *d_amul0,
    const unsigned int *d_amul1,
    const unsigned int *d_amul2,
    const unsigned int *d_amul3)
{
    unsigned int temp2;
    unsigned int nL1 = sub_k2_shared(state->R2 + state->B[4], gf2_table, gf3_table, d_s_box);
    unsigned int nR1 = sub_k2_shared(state->L2 + state->B[9], gf2_table, gf3_table, d_s_box);
    unsigned int nL2 = sub_k2_shared(state->L1, gf2_table, gf3_table, d_s_box);
    unsigned int nR2 = sub_k2_shared(state->R1, gf2_table, gf3_table, d_s_box);

    unsigned int nA[5];
    nA[0] = state->A[1];
    nA[1] = state->A[2];
    nA[2] = state->A[3];
    nA[3] = state->A[4];

    unsigned int nB[11];
    nB[0] = state->B[1];
    nB[1] = state->B[2];
    nB[2] = state->B[3];
    nB[3] = state->B[4];
    nB[4] = state->B[5];
    nB[5] = state->B[6];
    nB[6] = state->B[7];
    nB[7] = state->B[8];
    nB[8] = state->B[9];
    nB[9] = state->B[10];

    unsigned int temp1 = (state->A[0] << 8) ^ d_amul0[(state->A[0] >> 24) & 0xFF];
    nA[4] = temp1 ^ state->A[3];
    nA[4] ^= nlf(state->B[0], state->R2, state->R1, state->A[4]);

    if (state->A[2] & 0x40000000)
        temp1 = (state->B[0] << 8) ^ d_amul1[(state->B[0] >> 24) & 0xFF];
    else
        temp1 = (state->B[0] << 8) ^ d_amul2[(state->B[0] >> 24) & 0xFF];

    // branchless version (not faster)
    //  unsigned int mask = -(unsigned int)(!!(state->A[2] & 0x40000000));
    //  int b0 = state->B[0] << 8;
    //  int b0_24 = (state->B[0] >> 24) & 0xFF;
    //  unsigned int candidate1 = (b0) ^ d_amul1[b0_24];
    //  unsigned int candidate2 = (b0) ^ d_amul2[b0_24];
    //  temp1 = candidate2 ^ ((candidate1 ^ candidate2) & mask);

    if (state->A[2] & 0x80000000)
        temp2 = (state->B[8] << 8) ^ d_amul3[(state->B[8] >> 24) & 0xFF];
    else
        temp2 = state->B[8];

    // branchless version (not faster)    
    // unsigned int mask2 = -(unsigned int)(!!(state->A[2] & 0x80000000));
    // unsigned int candidate3 = (state->B[8] << 8) ^ d_amul3[(state->B[8] >> 24) & 0xFF];
    // unsigned int candidate4 = state->B[8];
    // temp2 = candidate4 ^ ((candidate3 ^ candidate4) & mask2);

    nB[10] = temp1 ^ state->B[1] ^ state->B[6] ^ temp2;
    nB[10] ^= nlf(state->B[10], state->L2, state->L1, state->A[0]);

    state->A[0] = nA[0];
    state->A[1] = nA[1];
    state->A[2] = nA[2];
    state->A[3] = nA[3];
    state->A[4] = nA[4];

    state->B[0] = nB[0];
    state->B[1] = nB[1];
    state->B[2] = nB[2];
    state->B[3] = nB[3];
    state->B[4] = nB[4];
    state->B[5] = nB[5];
    state->B[6] = nB[6];
    state->B[7] = nB[7];
    state->B[8] = nB[8];
    state->B[9] = nB[9];
    state->B[10] = nB[10];

    state->L1 = nL1;
    state->R1 = nR1;
    state->L2 = nL2;
    state->R2 = nR2;
}


__device__ __forceinline__ unsigned long long bswap64(unsigned long long x)
{
           uint32_t hi = x >> 32;  // Upper 32 bits
           uint32_t lo = x & 0xFFFFFFFF;  // Lower 32 bits       
           // Swap bytes in each 32-bit part using __byte_perm
           hi = __byte_perm(hi, 0, 0x0123);
           lo = __byte_perm(lo, 0, 0x0123);
       
           // Swap the high and low parts and combine them back
           return ((uint64_t)lo << 32) | hi;           
}

__device__ unsigned long long kcipher2_encrypt_1_zero_block(const unsigned int *key, const unsigned int *iv)
{
    kcipher2_state state;
    setup_state_values(key, iv, &state);
    for (unsigned char i = 0; i < 24; i++)
        next_INIT(&state);

    unsigned int zh = nlf(state.B[10], state.L2, state.L1, state.A[0]);
    unsigned int zl = nlf(state.B[0], state.R2, state.R1, state.A[4]);
    return (((unsigned long long)zh) << 32) | zl;
}

__device__ unsigned long long kcipher2_encrypt_1_zero_block_shared(const unsigned int *key, const unsigned int *iv, 
        const unsigned char *gf2_table, 
        const unsigned char *gf3_table, 
        const unsigned char *d_s_box,
        const unsigned int *d_amul0,
        const unsigned int *d_amul1,
        const unsigned int *d_amul2,
        const unsigned int *d_amul3
    )
{
    kcipher2_state state;
    setup_state_values_shared(key, iv, &state, gf2_table, gf3_table, d_s_box);
    for (unsigned char i = 0; i < 24; i++)
        next_INIT_shared(&state, gf2_table, gf3_table, d_s_box, d_amul0, d_amul1, d_amul2, d_amul3);

    unsigned int zh = nlf(state.B[10], state.L2, state.L1, state.A[0]);
    unsigned int zl = nlf(state.B[0], state.R2, state.R1, state.A[4]);
    return (((unsigned long long)zh) << 32) | zl;
}

//---------------------------------------------------------------------------
// End of file
//---------------------------------------------------------------------------



// --- Multihash Kernel ---
//
// Each thread computes:
//   digest0 = SHA256(19-byte input)
//   v0 = digest0
//   for i=1..1499:
//     buffer = digest(i-1) || v0 || [i as 4-byte big-endian]
//     digest(i) = SHA256(buffer)
// aes256_encrypt(&key_ctx, counter, counter);
// Encrypt the (now updated) counter to produce the final output.
// aes256_encrypt(&key_ctx, counter, digest);

// this kernel only output 16 byte random number
// but we output 32 byte block, so its like this <16 byte random> <16 byte empty> <16 byte random> <16 byte empty> ...
// This will make it faster

__global__ void multihash_kernel(const uint8_t *input, uint8_t *output, size_t num)
{
    ssize_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num)
        return;


    __shared__  uint32_t sha256_k[64];
    __shared__ unsigned char gf2_table_shared[256];
    __shared__ uint8_t aes_sbox[256];
    __shared__  uint32_t aes_Rcon[7];

    if (threadIdx.x == 0) {
        memcpy(sha256_k, k, sizeof(sha256_k));
        memcpy(aes_sbox, sbox, sizeof(aes_sbox));
        memcpy(aes_Rcon, Rcon, sizeof(aes_Rcon));
        memcpy(gf2_table_shared, gf2_table, sizeof(gf2_table_shared));
    }
    __syncthreads(); // Make sure the data is loaded before use


    // Each input message is 19 bytes.
    const uint8_t *data = input + idx * 19;
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t v0[SHA256_DIGEST_SIZE];

    // First round: hash the 19-byte input.
    // sha256_hash(data, 19, digest);

    sha256_hash_19(data, digest, sha256_k);

    // Save initial digest as v0.
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        v0[i] = digest[i];
    }
    uint8_t buffer[68]; // 32 bytes (digest) + 32 bytes (v0) + 4 bytes (counter)

    // Copy v0.
    for (int j = 0; j < SHA256_DIGEST_SIZE; j++)
    {
        buffer[32 + j] = v0[j];
    }

    // Write counter (big-endian).
    // buffer[64] = (i >> 24) & 0xff;
    // buffer[65] = (i >> 16) & 0xff;
    // max is 1500
    buffer[64] = 0;
    buffer[65] = 0;

    // 1,500 rounds total (first one is done above).
    for (int i = 1; i < 1500; i++)
    {
        // Copy current digest
	    #pragma unroll
        for (int j = 0; j < SHA256_DIGEST_SIZE; j++)
        {
            buffer[j] = digest[j];
        }

        buffer[66] = (i >> 8) & 0xff;
        buffer[67] = i & 0xff;

        // sha256_hash(buffer, 68, digest);
        sha256_hash_68(buffer, digest, sha256_k);
    }
#define AES_BLOCK_SIZE 16
    // -------- AES post-processing on final digest --------
    // Use final digest as the AES key.
    aes256_ctx key_ctx;
    aes256_set_encrypt_key(digest, &key_ctx, aes_sbox, aes_Rcon);
    uint8_t counter[16] = {0}; // clear counter

    // Encrypt the counter block.
    aes256_encrypt(&key_ctx, counter, counter, aes_sbox, gf2_table_shared);
    // Encrypt the (now updated) counter to produce the final output.
    aes256_encrypt(&key_ctx, counter, digest, aes_sbox, gf2_table_shared);

    // Write final (AES‑encrypted) digest to output.
    uint8_t *out = output + idx * SHA256_DIGEST_SIZE;

    uint32_t * out_u32 = (uint32_t *)out;
    uint32_t * digest_u32 = (uint32_t *)digest;

    //byte swap32 bit every 4 byte
    for (int i = 0; i < SHA256_DIGEST_SIZE / 4; i++)
    {
        out_u32[i] = __byte_perm(digest_u32[i], 0, 0x0123);
    }

}


__global__ void multihash_kernel_in_memory(uint8_t *output, uint64_t t_start, size_t num)
{
    ssize_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num)
        return;


    __shared__  uint32_t sha256_k[64];
    __shared__ unsigned char gf2_table_shared[256];
    __shared__ uint8_t aes_sbox[256];
    __shared__  uint32_t aes_Rcon[7];

    if (threadIdx.x == 0) {
        memcpy(sha256_k, k, sizeof(sha256_k));
        memcpy(aes_sbox, sbox, sizeof(aes_sbox));
        memcpy(aes_Rcon, Rcon, sizeof(aes_Rcon));
        memcpy(gf2_table_shared, gf2_table, sizeof(gf2_table_shared));
    }
    __syncthreads(); // Make sure the data is loaded before use
    uint64_t t = t_start + idx;

    // Each input message is 19 bytes.
    uint8_t data[19];
    for (int i =0; i < 19; i++) {
	    data[18-i]='0' + (t%10);
	    t /= 10;
    }
    
    uint8_t digest[SHA256_DIGEST_SIZE];
    // uint8_t v0[SHA256_DIGEST_SIZE];

    // First round: hash the 19-byte input.
    // sha256_hash(data, 19, digest);

    sha256_hash_19(data, digest, sha256_k);

    // Save initial digest as v0.
    // for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
    // {
    //     v0[i] = digest[i];
    // }
    uint8_t buffer[68]; // 32 bytes (digest) + 32 bytes (v0) + 4 bytes (counter)

    // Copy v0.
    for (int j = 0; j < SHA256_DIGEST_SIZE; j++)
    {
        buffer[32 + j] = digest[j];
    }

    // Write counter (big-endian).
    // buffer[64] = (i >> 24) & 0xff;
    // buffer[65] = (i >> 16) & 0xff;
    // max is 1500
    buffer[64] = 0;
    buffer[65] = 0;

    // 1,500 rounds total (first one is done above).
    for (int i = 1; i < 1500; i++)
    {
        // Copy current digest.
        for (int j = 0; j < SHA256_DIGEST_SIZE; j++)
        {
            buffer[j] = digest[j];
        }

        buffer[66] = (i >> 8) & 0xff;
        buffer[67] = i & 0xff;

        // sha256_hash(buffer, 68, digest);
        sha256_hash_68(buffer, digest, sha256_k);
    }
#define AES_BLOCK_SIZE 16
    // -------- AES post-processing on final digest --------
    // Use final digest as the AES key.
    aes256_ctx key_ctx;
    aes256_set_encrypt_key(digest, &key_ctx, aes_sbox, aes_Rcon);
    uint8_t counter[16] = {0}; // clear counter

    // Encrypt the counter block.
    aes256_encrypt(&key_ctx, counter, counter, aes_sbox, gf2_table_shared);
    // Encrypt the (now updated) counter to produce the final output.
    aes256_encrypt(&key_ctx, counter, digest, aes_sbox, gf2_table_shared);

    // Write final (AES‑encrypted) digest to output.
    uint8_t *out = output + idx * SHA256_DIGEST_SIZE;

    uint32_t * out_u32 = (uint32_t *)out;
    uint32_t * digest_u32 = (uint32_t *)digest;

    //byte swap32 bit every 4 byte
    for (int i = 0; i < SHA256_DIGEST_SIZE / 4; i++)
    {
        out_u32[i] = __byte_perm(digest_u32[i], 0, 0x0123);
    }

}

//this is for chacha8 key, so no need to swap, and we nseed the 32 byte block
__global__ void multihash_kernel_in_memory_no_swap(uint8_t *output, uint64_t t_start, size_t num)
{
    ssize_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num)
        return;


    __shared__  uint32_t sha256_k[64];
    __shared__ unsigned char gf2_table_shared[256];
    __shared__ uint8_t aes_sbox[256];
    __shared__  uint32_t aes_Rcon[7];

    if (threadIdx.x == 0) {
        memcpy(sha256_k, k, sizeof(sha256_k));
        memcpy(aes_sbox, sbox, sizeof(aes_sbox));
        memcpy(aes_Rcon, Rcon, sizeof(aes_Rcon));
        memcpy(gf2_table_shared, gf2_table, sizeof(gf2_table_shared));
    }
    __syncthreads(); // Make sure the data is loaded before use
    uint64_t t = t_start + idx;

    // Each input message is 19 bytes.
    uint8_t data[19];
    for (int i =0; i < 19; i++) {
	    data[18-i]='0' + (t%10);
	    t /= 10;
    }
    
    uint8_t digest[SHA256_DIGEST_SIZE];
    // uint8_t v0[SHA256_DIGEST_SIZE];

    // First round: hash the 19-byte input.
    // sha256_hash(data, 19, digest);

    sha256_hash_19(data, digest, sha256_k);

    // Save initial digest as v0.
    // for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
    // {
    //     v0[i] = digest[i];
    // }
    uint8_t buffer[68]; // 32 bytes (digest) + 32 bytes (v0) + 4 bytes (counter)

    // Copy v0.
    for (int j = 0; j < SHA256_DIGEST_SIZE; j++)
    {
        buffer[32 + j] = digest[j];
    }

    // Write counter (big-endian).
    // buffer[64] = (i >> 24) & 0xff;
    // buffer[65] = (i >> 16) & 0xff;
    // max is 1500
    buffer[64] = 0;
    buffer[65] = 0;

    // 1,500 rounds total (first one is done above).
    for (int i = 1; i < 1500; i++)
    {
        // Copy current digest.
        for (int j = 0; j < SHA256_DIGEST_SIZE; j++)
        {
            buffer[j] = digest[j];
        }

        buffer[66] = (i >> 8) & 0xff;
        buffer[67] = i & 0xff;

        // sha256_hash(buffer, 68, digest);
        sha256_hash_68(buffer, digest, sha256_k);
    }
#define AES_BLOCK_SIZE 16
    // -------- AES post-processing on final digest --------
    // Use final digest as the AES key.
    aes256_ctx key_ctx;
    aes256_set_encrypt_key(digest, &key_ctx, aes_sbox, aes_Rcon);
    uint8_t counter[16] = {0}; // clear counter

    // Encrypt the counter block.
    aes256_encrypt(&key_ctx, counter, counter, aes_sbox, gf2_table_shared);
    // Encrypt the (now updated) counter to produce the final output.
    aes256_encrypt(&key_ctx, counter, digest, aes_sbox, gf2_table_shared);

    // Write final (AES‑encrypted) digest to output.
    uint8_t *out = output + idx * SHA256_DIGEST_SIZE;

    #pragma unroll
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        out[i] = digest[i];
    }
}



//chacha8 key doesn't need swapping
__global__ void multihash_kernel_noswap(const uint8_t *input, uint8_t *output, size_t num)
{
    ssize_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= num)
        return;


    __shared__  uint32_t sha256_k[64];
    __shared__ unsigned char gf2_table_shared[256];
    __shared__ uint8_t aes_sbox[256];
    __shared__  uint32_t aes_Rcon[7];

    if (threadIdx.x == 0) {
        memcpy(sha256_k, k, sizeof(sha256_k));
        memcpy(aes_sbox, sbox, sizeof(aes_sbox));
        memcpy(aes_Rcon, Rcon, sizeof(aes_Rcon));
        memcpy(gf2_table_shared, gf2_table, sizeof(gf2_table_shared));
    }
    __syncthreads(); // Make sure the data is loaded before use


    // Each input message is 19 bytes.
    const uint8_t *data = input + idx * 19;
    uint8_t digest[SHA256_DIGEST_SIZE];
    uint8_t v0[SHA256_DIGEST_SIZE];

    // First round: hash the 19-byte input.
    // sha256_hash(data, 19, digest);

    sha256_hash_19(data, digest, sha256_k);

    // Save initial digest as v0.
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        v0[i] = digest[i];
    }
    uint8_t buffer[68]; // 32 bytes (digest) + 32 bytes (v0) + 4 bytes (counter)

    // Copy v0.
    for (int j = 0; j < SHA256_DIGEST_SIZE; j++)
    {
        buffer[32 + j] = v0[j];
    }

    // Write counter (big-endian).
    // buffer[64] = (i >> 24) & 0xff;
    // buffer[65] = (i >> 16) & 0xff;
    // max is 1500
    buffer[64] = 0;
    buffer[65] = 0;

    // 1,500 rounds total (first one is done above).
    for (int i = 1; i < 1500; i++)
    {
        // Copy current digest.
        for (int j = 0; j < SHA256_DIGEST_SIZE; j++)
        {
            buffer[j] = digest[j];
        }

        buffer[66] = (i >> 8) & 0xff;
        buffer[67] = i & 0xff;

        // sha256_hash(buffer, 68, digest);
        sha256_hash_68(buffer, digest, sha256_k);
    }
#define AES_BLOCK_SIZE 16
    // -------- AES post-processing on final digest --------
    // Use final digest as the AES key.
    aes256_ctx key_ctx;
    aes256_set_encrypt_key(digest, &key_ctx, aes_sbox, aes_Rcon);
    uint8_t counter[16] = {0}; // clear counter

    // Encrypt the counter block.
    aes256_encrypt(&key_ctx, counter, counter, aes_sbox, gf2_table_shared);
    // Encrypt the (now updated) counter to produce the final output.
    aes256_encrypt(&key_ctx, counter, digest, aes_sbox, gf2_table_shared);

    // Write final (AES‑encrypted) digest to output.
    uint8_t *out = output + idx * SHA256_DIGEST_SIZE;

     #pragma unroll
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++)
    {
        out[i] = digest[i];
    }
}



uint64_t get_time_in_nanosecond()
{
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return (uint64_t)time.tv_sec * 1000000000 + (uint64_t)time.tv_nsec;
}

#define TEST_ENCRYPT_BLOCK_SIZE 32

// Test kernel: each thread processes one key/IV pair.
// this is to test raw encryption speed
__global__ void test_kcipher2_kernel(const uint8_t *in, uint8_t *out, size_t N)
{
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= N)
        return;

    // Each input block: first 16 bytes = Key, next 16 bytes = IV.
    const int in_block_size = 32;                       // 16-byte key + 16-byte IV
    const int out_block_size = TEST_ENCRYPT_BLOCK_SIZE; // 128-byte ciphertext

    // Pointers to the key/IV for this thread.
    const uint8_t *block_in = in + idx * in_block_size;

    // Load key (16 bytes) and IV (16 bytes) into local arrays.
    unsigned int key_local[4];
    unsigned int iv_local[4];
    for (int i = 0; i < 4; i++)
    {
        int base_key = i * 4;
        key_local[i] = ((unsigned int)block_in[base_key] << 24) |
                       ((unsigned int)block_in[base_key + 1] << 16) |
                       ((unsigned int)block_in[base_key + 2] << 8) |
                       ((unsigned int)block_in[base_key + 3]);
    }
    for (int i = 0; i < 4; i++)
    {
        int base_iv = 16 + i * 4;
        iv_local[i] = ((unsigned int)block_in[base_iv] << 24) |
                      ((unsigned int)block_in[base_iv + 1] << 16) |
                      ((unsigned int)block_in[base_iv + 2] << 8) |
                      ((unsigned int)block_in[base_iv + 3]);
    }

    unsigned char ciphertext[8];

    long long res = kcipher2_encrypt_1_zero_block(key_local, iv_local);
    // copy res to ciphertext
    for (int i = 0; i < 8; i++)
    {
        ciphertext[i] = (res >> (56 - i * 8)) & 0xFF;
    }

    // Write the output ciphertext.
    size_t out_offset = idx * out_block_size;
    for (int i = 0; i < 8; i++)
    {
        out[out_offset + i] = ciphertext[i];
    }
}

void fill_input(uint8_t *h_input, uint64_t start, size_t num)
{
    char buffer[20];
    snprintf(buffer, 20, "%019lu", start);
    for (size_t i = 0; i < num; i++)
    {
        // copy buffer to input
        memcpy(h_input + i * 19, buffer, 19);
        // increment buffer, starting from last index, until it reaches '9'
        for (int j = 18; j >= 0; j--)
        {
            if (buffer[j] == '9')
            {
                buffer[j] = '0';
            }
            else
            {
                buffer[j]++;
                break;
            }
        }
    }
}

int test_encryption_only(size_t num)
{
    printf("Count %zu \n", num);
    size_t input_size = num * TEST_ENCRYPT_BLOCK_SIZE;

    // Query device properties
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, gpuIndex);

    int maxThreadsPerBlock = prop.maxThreadsPerBlock; // Maximum allowed per block
    int blockSize = maxThreadsPerBlock;               // Dynamically set blockSize
    // int blockSize = 256;
    int gridSize = (num + blockSize - 1) / blockSize; // Ensure full coverage

    printf("Using blockSize = %d, gridSize = %d\n", blockSize, gridSize);

    size_t output_size = num * TEST_ENCRYPT_BLOCK_SIZE;

    printf("GPU needed memory: %.2f MB\n", (input_size + output_size) / 1024.0 / 1024.0);

    uint8_t *h_input = (uint8_t *)malloc(input_size);
    // test the blank/zero encryption
    // memset(h_input, 0, input_size);
    // fill with random
    fill_input(h_input, TEST_TIMESTAMP, num * (32 / 19));

    uint8_t *h_output_enc = (uint8_t *)malloc(output_size);

    // Allocate device memory.
    uint8_t *d_input, *d_output_enc;

    printf("Allocating device memory...%.2f Mb\n", (input_size + output_size) / 1024.0 / 1024.0);

    if (cudaMalloc(&d_input, input_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_input\n");
        return 1;
    }
    if (cudaMalloc(&d_output_enc, output_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_output_enc\n");
        return 1;
    }
    uint64_t start = get_time_in_nanosecond();

    // copy to device
    cudaMemcpy(d_input, h_input, input_size, cudaMemcpyHostToDevice);

    test_kcipher2_kernel<<<gridSize, blockSize>>>(d_input, d_output_enc, num);
    cudaDeviceSynchronize();

    // debug encryption output
    cudaMemcpy(h_output_enc, d_output_enc, output_size, cudaMemcpyDeviceToHost);

    uint64_t end = get_time_in_nanosecond();

    printf("Enc Time: %f ms\n", (end - start) / 1000000.0);

    // print speed
    printf("Enc Speed: %f enc per second\n", num / ((end - start) / 1000000000.0));

    // print first plaintext
    printf("Plaintext for first input: ");
    for (size_t i = 0; i < 19; i++)
    {
        printf("%c", h_input[i]);
    }
    printf("\n");

    // For demonstration, print the first output digest in hexadecimal.
    printf("Encrypted for first input: ");
    for (size_t i = 0; i < TEST_ENCRYPT_BLOCK_SIZE; i++)
    {
        printf("%02x", h_output_enc[i]);
    }
    printf("\n");
    // print last
    // print plaintext
    printf("Plaintext for last input: ");
    for (size_t i = 19 * num - 19; i < 19 * num; i++)
    {
        printf("%c", h_input[i]);
    }
    printf("\n");
    printf("Encrypted for last input: offs <%zu>: ", num * TEST_ENCRYPT_BLOCK_SIZE - TEST_ENCRYPT_BLOCK_SIZE);
    for (size_t i = TEST_ENCRYPT_BLOCK_SIZE * num - TEST_ENCRYPT_BLOCK_SIZE; i < TEST_ENCRYPT_BLOCK_SIZE * num; i++)
    {
        printf("%02x", h_output_enc[i]);
    }
    printf("\n");

    // Cleanup.
    cudaFree(d_input);
    cudaFree(d_output_enc);
    free(h_input);
    free(h_output_enc);

    return 0;
}

#define DIGEST_SIZE 32
#define KEY_IV_SIZE 16 // we use first 16 bytes for key/iv
#define KCIPHER_OUT_SIZE 8

// KCIPHER2, single kernel

// --- Host Code ---

//for testing only, it will save all random number generated from a given second

int save_random(uint64_t start_time, const char *filename)
{
    printf("Saving all seeds for %lu to %s\n", start_time, filename);

    uint64_t timer_start = get_time_in_nanosecond();

    //do it for every 10 million
    size_t num = 10*1000*1000;
    size_t input_size = num * 19 * sizeof(uint8_t);
    uint8_t *h_input = (uint8_t *)malloc(input_size);
    size_t output_size = num * SHA256_DIGEST_SIZE * sizeof(uint8_t);
    uint8_t *h_output = (uint8_t *)malloc(output_size);

    uint8_t *h_output_non_zeroes = (uint8_t *)malloc(num * 16);

    // Allocate device memory.
    uint8_t *d_input, *d_output;
    if (cudaMalloc(&d_input, input_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_input\n");
        return 1;
    }
    if (cudaMalloc(&d_output, output_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_output\n");
        return 1;
    }

    int blockSize = 256;
    int gridSize = (num + blockSize - 1) / blockSize; // Ensure full coverage
    printf("Using blockSize = %d, gridSize = %d\n", blockSize, gridSize);

    FILE *f = fopen(filename, "wb");
    if (f == NULL)
    {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return 1;
    }

    for (size_t i = 0; i < 100; i++) {
        printf("Saving %zu %%\r", i);fflush(stdout);
        fill_input(h_input, start_time + i * num, num); 
        //copy to CUDA
        cudaMemcpy(d_input, h_input, input_size, cudaMemcpyHostToDevice);

        multihash_kernel<<<gridSize, blockSize>>>(d_input, d_output, num);
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess)
        {
            fprintf(stderr, "Error: %s\n", cudaGetErrorString(err));
            return 1;
        }
        cudaDeviceSynchronize();        
        cudaMemcpy(h_output, d_output, output_size, cudaMemcpyDeviceToHost);
        //copy every 16 bytes
        for (size_t j = 0; j < num; j++)
        {
            memcpy(h_output_non_zeroes + j * 16, h_output + j * DIGEST_SIZE, 16);
        }
        fwrite(h_output_non_zeroes, 16, num, f);

    }
    fclose(f);
    uint64_t timer_end = get_time_in_nanosecond();

    printf("DONE saved to %s: total time %.2f second \n", filename, (timer_end - timer_start) / 1000000000.0);
    
    return 0;
}

int test_generate_random_only_in_gpu(size_t num)
{
    uint64_t t_start = TEST_TIMESTAMP + 2000; // TEST:  0 is for chacha, +1000 for chacha_nonce	

    size_t output_size = num * SHA256_DIGEST_SIZE * sizeof(uint8_t);
    printf("Output size: %.2f MB\n", output_size / 1024.0 / 1024.0);
    uint8_t *h_output = (uint8_t *)malloc(output_size);

    uint8_t *d_output;
    if (cudaMalloc(&d_output, output_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_output\n");
        return 1;
    }
    int blockSize = 256;
    int gridSize = (num + blockSize - 1) / blockSize; // Ensure full coverage
    uint64_t start = get_time_in_nanosecond();
    multihash_kernel_in_memory<<<gridSize, blockSize>>>(d_output, t_start, num);
    cudaDeviceSynchronize();
    uint64_t end = get_time_in_nanosecond();    
    cudaMemcpy(h_output, d_output, output_size, cudaMemcpyDeviceToHost);

    // print first and last
    printf("First random ");
    for (int i = 0; i < DIGEST_SIZE; i++)
    {
        printf("%02x", h_output[i]);
    }
    printf("\n");
    printf("Last random ");
    for (size_t i = DIGEST_SIZE * num - DIGEST_SIZE; i < DIGEST_SIZE * num; i++)
    {
        printf("%02x", h_output[i]);
    }
    printf("\n");

    printf("Total Time: %f ms\n", (end - start) / 1000000.0);
    printf("Speed: %f hashes per second\n", num / ((end - start) / 1000000000.0));
    
    
    return 0;    
}

int test_generate_random_only(size_t num)
{
    printf("Test generate random only: %lu\n", num);
    size_t input_size = num * 19 * sizeof(uint8_t);
    printf("Input size: %.2f MB\n", input_size / 1024.0 / 1024.0);

    // Allocate host memory.
    uint8_t *h_input = (uint8_t *)malloc(input_size);

    uint64_t t_start = TEST_TIMESTAMP + 2000; // TEST:  0 is for chacha, +1000 for chacha_nonce

    // output
    size_t output_size = num * SHA256_DIGEST_SIZE * sizeof(uint8_t);
    printf("Output size: %.2f MB\n", output_size / 1024.0 / 1024.0);

    uint8_t *h_output = (uint8_t *)malloc(output_size);

    uint64_t start_fill = get_time_in_nanosecond();

    fill_input(h_input, t_start, num);
    uint64_t end_fill = get_time_in_nanosecond();
    printf("Fill Time: %f ms\n", (end_fill - start_fill) / 1000000.0);

    // Allocate device memory.
    uint8_t *d_input, *d_output;
    if (cudaMalloc(&d_input, input_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_input\n");
        return 1;
    }
    if (cudaMalloc(&d_output, output_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_output\n");
        return 1;
    }

    uint64_t start = get_time_in_nanosecond();

    cudaMemcpy(d_input, h_input, input_size, cudaMemcpyHostToDevice);

    int blockSize = 256;
    int gridSize = (num + blockSize - 1) / blockSize; // Ensure full coverage

    printf("Using blockSize = %d, gridSize = %d\n", blockSize, gridSize);

    printf("Starting timestamp -> random calculation...\n");
    fflush(stdout);

    multihash_kernel<<<gridSize, blockSize>>>(d_input, d_output, num);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Error: %s\n", cudaGetErrorString(err));
        return 1;
    }

    cudaDeviceSynchronize();
    uint64_t end1 = get_time_in_nanosecond();
    cudaMemcpy(h_output, d_output, output_size, cudaMemcpyDeviceToHost);

    uint64_t end = get_time_in_nanosecond();

    // print first and last
    printf("First random ");
    for (int i = 0; i < DIGEST_SIZE; i++)
    {
        printf("%02x", h_output[i]);
    }
    printf("\n");
    printf("Last random ");
    for (size_t i = DIGEST_SIZE * num - DIGEST_SIZE; i < DIGEST_SIZE * num; i++)
    {
        printf("%02x", h_output[i]);
    }
    printf("\n");

    printf("Total Time: %f ms\n", (end - start) / 1000000.0);
    // print speed per second
    printf("Speed: %f hashes per second\n", num / ((end1 - start) / 1000000000.0));
    // Cleanup.
    cudaFree(d_input);
    cudaFree(d_output);
    free(h_input);
    free(h_output);
    return 0;
}


#define U8TO32_LITTLE(p) (*(const uint32_t *)(p))

typedef struct {
    uint32_t a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p;
} BLOCK;


// Device helper: rotate left 32-bit value
__device__ __forceinline__ uint32_t _rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}


#define QROUND(a, b, c, d)       \
    d = _rotl(d ^ (a += b), 16); \
    b = _rotl(b ^ (c += d), 12); \
    d = _rotl(d ^ (a += b), 8);  \
    b = _rotl(b ^ (c += d), 7)
#define FROUND                  \
    QROUND(x.d, x.h, x.l, x.p); \
    QROUND(x.c, x.g, x.k, x.o); \
    QROUND(x.b, x.f, x.j, x.n); \
    QROUND(x.a, x.e, x.i, x.m); \
    QROUND(x.a, x.f, x.k, x.p); \
    QROUND(x.b, x.g, x.l, x.m); \
    QROUND(x.c, x.h, x.i, x.n); \
    QROUND(x.d, x.e, x.j, x.o)
#define FFINAL  \
    x.a += j.a; \
    x.b += j.b; \
    x.c += j.c; \
    x.d += j.d; \
    x.e += j.e; \
    x.f += j.f; \
    x.g += j.g; \
    x.h += j.h; \
    x.i += j.i; \
    x.j += j.j; \
    x.k += j.k; \
    x.l += j.l; \
    x.m += j.m; \
    x.n += j.n; \
    x.o += j.o; \
    x.p += j.p

//in contains key/nonce
//offset is the match offset
//out_flag is the flag: ts << 32 | offset
__global__ void chacha8_encrypt_and_match(const uint8_t *in, size_t offset,
    unsigned long long *out_flag,
    const unsigned long long value,
    int N)
{
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx >= N)
    {
        return;
    }

    size_t idx_offs = idx + offset;

    if (idx_offs >= N)
    {
        return;
    }

    const int in_block_size = 32;

    // Pointers to the key/IV for this thread.
    const uint8_t *block_in = in + idx * in_block_size;
    const uint8_t *block_offset_in = in + idx_offs * in_block_size;

    const uint8_t *k = block_in;
    const uint8_t *iv = block_offset_in;
    const char constants[16] = {'e', 'x', 'p', 'a', 'n', 'd', ' ', '1', '6', '-', 'b', 'y', 't', 'e', ' ', 'k'};


    uint32_t state[16];
    state[4] = U8TO32_LITTLE(k + 0);
    state[5] = U8TO32_LITTLE(k + 4);
    state[6] = U8TO32_LITTLE(k + 8);
    state[7] = U8TO32_LITTLE(k + 12);
    state[8] = U8TO32_LITTLE(k + 0);
    state[9] = U8TO32_LITTLE(k + 4);
    state[10] = U8TO32_LITTLE(k + 8);
    state[11] = U8TO32_LITTLE(k + 12);
    state[0] = U8TO32_LITTLE(constants + 0);
    state[1] = U8TO32_LITTLE(constants + 4);
    state[2] = U8TO32_LITTLE(constants + 8);
    state[3] = U8TO32_LITTLE(constants + 12);
    state[12] = 0;
    state[13] = 0;
    state[14] = U8TO32_LITTLE(iv + 0);
    state[15] = U8TO32_LITTLE(iv + 4);

    BLOCK x;
    BLOCK j;

    memcpy(&j, state, sizeof(BLOCK)); //j is for final addition
    j.m = 0;
    j.n = 0;

    memcpy(&x, &j, sizeof(BLOCK)); //FROUND will modify x

    FROUND;
    FROUND;
    FROUND;
    FROUND;
    FFINAL;

    uint64_t *result = (uint64_t *)&x;
    if (*result == value) {
        unsigned long long encoded_offset_and_index = (unsigned long long)offset << 32 | idx;
        *out_flag = encoded_offset_and_index;
    }

}

__global__ void encrypt_and_search_offset(const uint8_t *in, size_t offset,
                                          unsigned long long *out_flag,
                                          const unsigned long long *masks,
                                          const unsigned long long *values,
                                          int numComb,
                                          int N)
{
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;

    if (idx >= N)
    {
        return;
    }

    size_t idx_offs = idx + offset;

    // FIX: idx_offs indexes the full `num`-sized hash array, NOT N (=limit).
    // The host guarantees idx_offs < num whenever idx < N, so the old guard
    // `if (idx_offs >= N) return;` wrongly discarded valid T3 candidates in
    // [N-offset, N) and, when offset >= N, returned for EVERY thread (searching
    // nothing). No bound needed here.


    __shared__ unsigned char gf2_table_shared[256];
    __shared__ unsigned char gf3_table_shared[256];
    __shared__ unsigned char d_s_box_shared[256];
    __shared__ unsigned int d_amul0_shared[256];
    __shared__ unsigned int d_amul1_shared[256];
    __shared__ unsigned int d_amul2_shared[256];
    __shared__ unsigned int d_amul3_shared[256];
    __shared__ unsigned long long shared_masks[MAX_MATCHES];
    __shared__ unsigned long long shared_values[MAX_MATCHES];

    if (threadIdx.x == 0) {
        //copy gf2_table from const
        memcpy(gf2_table_shared, gf2_table, 256);
        memcpy(gf3_table_shared, gf3_table, 256);
        memcpy(d_s_box_shared, d_s_box, 256);
        memcpy(d_amul0_shared, d_amul0, 256 * sizeof(int));
        memcpy(d_amul1_shared, d_amul1, 256 * sizeof(int));
        memcpy(d_amul2_shared, d_amul2, 256 * sizeof(int));
        memcpy(d_amul3_shared, d_amul3, 256 * sizeof(int));
        for (int i = 0; i < numComb; i++)
        {
            shared_masks[i] = masks[i];
            shared_values[i] = values[i];
        }
    }
    __syncthreads(); // Make sure the data is loaded before use
    

    const int in_block_size = 32;

    // Pointers to the key/IV for this thread.
    const uint8_t *block_in = in + idx * in_block_size;
    const uint8_t *block_offset_in = in + idx_offs * in_block_size;

    // Load key (16 bytes) and IV (16 bytes) into local arrays.
    unsigned int key_local[4];
    unsigned int iv_local[4];
    const uint8_t *key_in = block_in;


    const uint8_t *iv_in = block_offset_in;

    memcpy(key_local, key_in, 16);


    memcpy(iv_local, iv_in, 16);

    //long long res = kcipher2_encrypt_1_zero_block(key_local, iv_local);
    long long res = kcipher2_encrypt_1_zero_block_shared(key_local, iv_local, gf2_table_shared, gf3_table_shared, d_s_box_shared,
        d_amul0_shared, d_amul1_shared, d_amul2_shared, d_amul3_shared);


    // compare with matches
    unsigned long long in_val = bswap64(res);

    unsigned int flag = 0;

    for (int i = 0; i < numComb; i++) {
        // diff is 0 if the masked input equals the expected value
        unsigned long long diff = (in_val & shared_masks[i]) ^ shared_values[i];
        // Compute a branch-free match: returns nonzero if diff is zero.
        flag |= (1 - ((diff | -diff) >> 63));   
    }
    if (flag) {
        //we found it, now find out exactly which one did we find
        for (int i = 0; i < numComb; i++) {
            if ((in_val & shared_masks[i]) == shared_values[i]) {
                //idx: max 1 billion, use 30 bits
                //offset: max 64 million, use 26
                //numComb: max 128, use 7
                unsigned long long encoded_offset_and_index = (unsigned long long)(idx << 34 | offset << 8 | i << 1 | 1);

                *out_flag = encoded_offset_and_index;

                break;
            }
        }
    }

}

void decode_offset_and_index(unsigned long long encoded_offset_and_index, 
                        size_t *offset, size_t *index, size_t *matchPos)
{
    //idx: max 1 billion, use 30 bits
    //offset: max 64 million, use 26
    //matchPos: max 128, use 7 bits
    //final 1 bit to ensure we have true value    
    //how it was encoded:
    //unsigned long long encoded_offset_and_index = (unsigned long long)(idx << 34 | offset << 8 | i << 1 | 1);                
    //decode:
    *index = (encoded_offset_and_index >> 34) & 0x3fffffff;
    *offset = (encoded_offset_and_index >> 8) & 0x3ffffff;
    *matchPos = (encoded_offset_and_index >> 1) & 0x7f;
}

__global__ void encrypt_and_search(const uint8_t *in, uint8_t *out, uint32_t k1, uint32_t k2, uint32_t k3, uint32_t k4,
                                   int *out_flag,
                                   const unsigned long long *masks,
                                   const unsigned long long *values,
                                   int numComb,
                                   int N)
{
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= N)
        return;

    // for (int i =0; i < 16; i++) {
    //     printf("%02x", in[i]);
    // }
    // printf("\n");

    // Each input block: first 16 bytes = Key, next 16 bytes = IV.
    const int in_block_size = 32;                       // 16-byte IV + zeroes
    const int out_block_size = TEST_ENCRYPT_BLOCK_SIZE; // block size

    // Pointers to the key/IV for this thread.
    const uint8_t *block_in = in + idx * in_block_size;

    // Load key (16 bytes) and IV (16 bytes) into local arrays.
    __shared__ unsigned int key_local[4];

    __shared__ unsigned char gf2_table_shared[256];
    __shared__ unsigned char gf3_table_shared[256];
    __shared__ unsigned char d_s_box_shared[256];
    __shared__ unsigned int d_amul0_shared[256];
    __shared__ unsigned int d_amul1_shared[256];
    __shared__ unsigned int d_amul2_shared[256];
    __shared__ unsigned int d_amul3_shared[256];
    __shared__ unsigned long long shared_masks[MAX_MATCHES];
    __shared__ unsigned long long shared_values[MAX_MATCHES];

    unsigned int iv_local[4];
    if (threadIdx.x == 0) {
        key_local[0] = k1;
        key_local[1] = k2;
        key_local[2] = k3;
        key_local[3] = k4;
        //copy gf2_table from const
        memcpy(gf2_table_shared, gf2_table, 256);
        memcpy(gf3_table_shared, gf3_table, 256);
        memcpy(d_s_box_shared, d_s_box, 256);
        memcpy(d_amul0_shared, d_amul0, 256 * sizeof(int));
        memcpy(d_amul1_shared, d_amul1, 256 * sizeof(int));
        memcpy(d_amul2_shared, d_amul2, 256 * sizeof(int));
        memcpy(d_amul3_shared, d_amul3, 256 * sizeof(int));
        for (int i = 0; i < numComb; i++)
        {
            shared_masks[i] = masks[i];
            shared_values[i] = values[i];
        }
    }
    __syncthreads(); // Make sure the data is loaded before use

    const uint8_t *iv_in = block_in;

    
    memcpy(iv_local, iv_in,16);

    //long long res = kcipher2_encrypt_1_zero_block(key_local, iv_local);
    long long res = kcipher2_encrypt_1_zero_block_shared(key_local, iv_local, gf2_table_shared, gf3_table_shared, d_s_box_shared,
        d_amul0_shared, d_amul1_shared, d_amul2_shared, d_amul3_shared);

    // compare with matches
    unsigned long long in_val = bswap64(res);
    unsigned int flag = 0;
    for (int i = 0; i < numComb; i++)
    {
        if ((in_val & masks[i]) == values[i])
        {
            *out_flag = 1;
            flag = 1;
            break;
        }
    }


#if 1
#ifdef NUM_MATCHES    
    #pragma unroll
    for (int i = 0; i < NUM_MATCHES; i++) {
#else
    for (int i = 0; i < numComb; i++) {
#endif        

        // diff is 0 if the masked input equals the expected value
        unsigned long long diff = (in_val & shared_masks[i]) ^ shared_values[i];
        // Compute a branch-free match: returns nonzero if diff is zero.
        flag |= (1 - ((diff | -diff) >> 63));   
    }
    if (flag)
        *out_flag = flag;

#endif
        
    if (flag)
    {
        // Write the output ciphertext.
        int out_offset = idx * out_block_size;
#pragma unroll
        for (int i = 0; i < 8; i++) // only copy changed
        {
            out[out_offset + i] = (res >> (56 - i * 8)) & 0xFF;
        }
    }
}



int do_bruteforce_offset(const char *filename)
{
    printf("Bruteforce Offset\n");
    json config;

    std::string json_file = filename;

    std::string checkpoint = json_file + ".checkpoint.json";

    std::ifstream f(filename);
    if (!f.is_open())
    {
        fprintf(stderr, "Error: Could not open config file %s\n", filename);
        return 1;
    }

    try
    {
        f >> config;
    }
    catch (json::parse_error &e)
    {
        fprintf(stderr, "Error parsing JSON: %s\n", e.what());
        return 1;
    }

    size_t *offsets = 0;
    size_t offset_count = 0;
    //open offset.txt
    FILE *f_offset = fopen("offset.txt", "r");
    if (f_offset == NULL)
    {
        fprintf(stderr, "Error: Could not open offset file\n");
        return 1;
    }
    //read line by line, convert to integer
    char line[256];
    while (fgets(line, sizeof(line), f_offset))
    {
        offsets = (size_t *)realloc(offsets, (offset_count + 1) * sizeof(size_t));
        offsets[offset_count] = strtoull(line, NULL, 10);
        offset_count++;
    }
    fclose(f_offset);
    printf("Offset count: %zu\n", offset_count);
    //print first and last offset
    printf("First offset: %zu\n", offsets[0]);
    printf("Last offset: %zu\n", offsets[offset_count - 1]);


    size_t num;
    uint64_t t_start;
    //size_t enc_count;
    size_t offset;

    size_t matches_size = 0;
    uint64_t *matches = 0;
    uint64_t *masks = 0;

    try
    {
        t_start = config["start_timestamp"].get<uint64_t>(); // start T3

        num = config["count"].get<size_t>(); // stop at T3 + count ns

        offset = config["offset"].get<size_t>(); // we start at T3 + offset ns

        //enc_count = config["brute_force_time_range"].get<size_t>(); // we stop at T3 + offset + enc_count ns

        // "mathes": [
        //     {
        //         "plaintext": "0x00000000",
        //         "encrypted": "0x00000000",
        //         "bitmask": "0xffffffff"
        //     },
        //     {
        //         "plaintext": "0x00000000",
        //         "encrypted": "0x00000001",
        //         "bitmask": "0xffffffff"
        //     }
        // ]
        // parse matches, and put it in array (match = plaintext^encrypted)
        if (config.contains("matches"))
        {
            matches_size = config["matches"].size();
            assert(matches_size < MAX_MATCHES);
            assert(matches_size > 0);
            matches = (uint64_t *)malloc(matches_size * sizeof(uint64_t));
            masks = (uint64_t *)malloc(matches_size * sizeof(uint64_t));
            for (size_t i = 0; i < matches_size; i++)
            {
                uint64_t plaintext = std::stoull(config["matches"][i]["plaintext"].get<std::string>(), 0, 16);
                uint64_t encrypted = std::stoull(config["matches"][i]["encrypted"].get<std::string>(), 0, 16);
                uint64_t bitmask = std::stoull(config["matches"][i]["bitmask"].get<std::string>(), 0, 16);
                matches[i] = plaintext ^ encrypted;
                masks[i] = bitmask;
                printf("Match %zu: %016lx bitmask %016lx \n", i, matches[i], masks[i]);
            }
            
        }
    }
    catch (json::exception &e)
    {
        fprintf(stderr, "Error reading JSON values: %s\n", e.what());
        return 1;
    }

    printf("Configuration:\n");
    printf("num: %zu\n", num);
    printf("t_start: %lu\n", t_start);
    //printf("enc_count: %zu\n", enc_count);
    printf("offset: %zu\n", offset);

    //printf("Brute forcing: %zu enc count %zu\n", num, enc_count);
    size_t input_size = num * 19 * sizeof(uint8_t);
    printf("Input size: %.2f MB\n", input_size / 1024.0 / 1024.0);

    // Allocate host memory.
    uint8_t *h_input = (uint8_t *)malloc(input_size);

    // output
    size_t output_size = num * SHA256_DIGEST_SIZE * sizeof(uint8_t);
    printf("Output size: %.2f MB\n", output_size / 1024.0 / 1024.0);

    uint8_t *h_output = (uint8_t *)malloc(output_size);

    //size_t enc_output_size = enc_count * TEST_ENCRYPT_BLOCK_SIZE * sizeof(uint8_t);

    //uint8_t *h_output_enc = (uint8_t *)malloc(enc_output_size);

    uint64_t start_fill = get_time_in_nanosecond();

    fill_input(h_input, t_start, num); // GENERATE TS

    uint64_t end_fill = get_time_in_nanosecond();
    printf("Fill Time: %f ms\n", (end_fill - start_fill) / 1000000.0);

    // Allocate device memory.
    uint8_t *d_input, *d_output;
    //uint8_t *d_output_enc;
    unsigned long long *d_found;
    unsigned long long *d_matches;
    unsigned long long *d_masks;

    if (cudaMalloc(&d_input, input_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_input\n");
        return 1;
    }
    if (cudaMalloc(&d_output, output_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_output\n");
        return 1;
    }
    // if (cudaMalloc(&d_output_enc, enc_output_size) != cudaSuccess)
    // {
    //     fprintf(stderr, "Error: cudaMalloc failed for d_output_enc\n");
    //     return 1;
    // }
    if (cudaMalloc(&d_found, sizeof(unsigned long long)) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_found\n");
        return 1;
    }
    if (cudaMalloc(&d_matches, matches_size * sizeof(uint64_t)) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_matches\n");
        return 1;
    }
    if (cudaMalloc(&d_masks, matches_size * sizeof(uint64_t)) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_masks\n");
        return 1;
    }

    unsigned long long zero = 0;
    cudaMemcpy(d_found, &zero, sizeof(unsigned long long), cudaMemcpyHostToDevice);

    // copy matches and masks
    cudaMemcpy(d_matches, matches, matches_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_masks, masks, matches_size * sizeof(uint64_t), cudaMemcpyHostToDevice);

    uint64_t start = get_time_in_nanosecond();

    cudaMemcpy(d_input, h_input, input_size, cudaMemcpyHostToDevice);

    // Launch kernel.
    int blockSize = 256;
    int gridSize = (num + blockSize - 1) / blockSize;

    printf("Using blockSize = %d, gridSize = %d\n", blockSize, gridSize);

    printf("Starting timestamp -> random calculation...\n");

    multihash_kernel<<<gridSize, blockSize>>>(d_input, d_output, num);
    cudaDeviceSynchronize();
    uint64_t end1 = get_time_in_nanosecond();

    uint64_t end = get_time_in_nanosecond();

    int limit = num - offset;

    printf("Total Time: %f ms\n", (end - start) / 1000000.0);
    // print speed per second
    printf("Speed: %f hashes per second\n", num / ((end1 - start) / 1000000000.0));

    printf("Limit: %d\n", limit);
    start = get_time_in_nanosecond();

    uint64_t start_enc = get_time_in_nanosecond();

    // set gridsize based on limit
    gridSize = (limit + blockSize - 1) / blockSize;

    for (size_t i = 0; i < offset_count; i++) 
    {
        printf("Starting encryption and search at offset %zu (%zu)\n", i, offsets[i]);
        encrypt_and_search_offset<<<gridSize, blockSize>>>(d_output, offsets[i], d_found, d_masks, d_matches, matches_size, limit);
        //check for error
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess)
        {
            fprintf(stderr, "Error: %s\n", cudaGetErrorString(err));
            return 1;
        }

        if (i > 0 && (i % 1) == 0)
        {
            uint64_t end_enc = get_time_in_nanosecond();
            printf("Enc Time: %f ms\n", (end_enc - start_enc) / 1000000.0);
            start_enc = get_time_in_nanosecond();
            printf("Progress: %zu/%zu (testing: %zu)\n", i, offset_count, offsets[i]);
            cudaDeviceSynchronize();

            unsigned long long found = 0;
            cudaMemcpy(&found, d_found, sizeof(unsigned long long), cudaMemcpyDeviceToHost);
            if (found)
            {
                //unsigned long long encoded_offset_and_index = (unsigned long long)offset << 31 | idx << 1 | 1;

                size_t t_offset, t_index, match_pos;
                decode_offset_and_index(found, &t_offset, &t_index, &match_pos);

                printf("Found at  index %zu  offset=%zu ts = %zu + %zu filename = %s match_pos = %zu\n", i, t_offset, t_start, t_index, filename, match_pos);
                //write to output.txt
                FILE *f = fopen("output.txt", "a");
                if (f == NULL)
                {
                    printf("Error opening file!\n");
                    exit(1);
                }
                fprintf(f, "Found at  index %zu  offset=%zu ts = %zu + %zu filename = %s match_pos = %zu\n", i, t_offset, t_start, t_index, filename, match_pos);
                fclose(f);
                // reset for next
                cudaMemcpy(d_found, &zero, sizeof(unsigned long long), cudaMemcpyHostToDevice);
                // err = cudaGetLastError();
                // if (err != cudaSuccess)
                // {
                //     fprintf(stderr, "Error2: %s\n", cudaGetErrorString(err));
                //     return 1;
                // }
            }
            //write checkpoint
            config["start_timestamp"] = t_start + i;
            config["index"] = i;
            std::ofstream o(checkpoint);
            o << std::setw(4) << config << std::endl;            
        }
    }

    cudaDeviceSynchronize();

    long long found = 0;
    cudaMemcpy(&found, d_found, sizeof(unsigned long long), cudaMemcpyDeviceToHost);
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Error: %s\n", cudaGetErrorString(err));
        return 1;
    }
    if (found)
    {
        size_t t_offset, t_index, match_pos;
        decode_offset_and_index(found, &t_offset, &t_index, &match_pos);
        printf("Found at  offset=%zu ts = %zu + %zu filename = %s match indxex = %zu\n",  t_offset, t_start, t_index, filename, match_pos);

    }

    uint64_t end_enc = get_time_in_nanosecond();
    printf("Enc Offset list Time: %f ms\n", (end_enc - start_enc) / 1000000.0);

    return 0;
}

int do_bruteforce_new(const char *filename)
{
    json config;

    std::string json_file = filename;

    std::string checkpoint = json_file + ".checkpoint.json";

    std::ifstream f(filename);
    if (!f.is_open())
    {
        fprintf(stderr, "Error: Could not open config file %s\n", filename);
        return 1;
    }

    try
    {
        f >> config;
    }
    catch (json::parse_error &e)
    {
        fprintf(stderr, "Error parsing JSON: %s\n", e.what());
        return 1;
    }

    size_t num;
    uint64_t t_start;
    size_t enc_count;
    size_t offset;

    size_t matches_size = 0;
    uint64_t *matches = 0;
    uint64_t *masks = 0;
    char **matches_filename = 0;

    try
    {
        t_start = config["start_timestamp"].get<uint64_t>(); // start T3

        num = config["count"].get<size_t>(); // stop at T3 + count ns

        offset = config["offset"].get<size_t>(); // we start at T3 + offset ns

        enc_count = config["brute_force_time_range"].get<size_t>(); // we stop at T3 + offset + enc_count ns

        // parse matches, and put it in array (match = plaintext^encrypted)
        if (config.contains("matches"))
        {
            matches_size = config["matches"].size();

            assert(matches_size < MAX_MATCHES);
            assert(matches_size > 0);

            matches = (uint64_t *)malloc(matches_size * sizeof(uint64_t));
            masks = (uint64_t *)malloc(matches_size * sizeof(uint64_t));
            matches_filename = (char **)malloc(matches_size * sizeof(char *));
            for (size_t i = 0; i < matches_size; i++)
            {
                uint64_t plaintext = std::stoull(config["matches"][i]["plaintext"].get<std::string>(), 0, 16);
                uint64_t encrypted = std::stoull(config["matches"][i]["encrypted"].get<std::string>(), 0, 16);
                uint64_t bitmask = std::stoull(config["matches"][i]["bitmask"].get<std::string>(), 0, 16);
                std::string filename = config["matches"][i]["filename"].get<std::string>();
                //strdup filename
                matches_filename[i] = strdup(filename.c_str());
                matches[i] = plaintext ^ encrypted;
                masks[i] = bitmask;
                printf("Match %zu: %016lx bitmask %016lx \n", i, matches[i], masks[i]);

            }
        }
    }
    catch (json::exception &e)
    {
        fprintf(stderr, "Error reading JSON values: %s\n", e.what());
        return 1;
    }

    printf("Configuration:\n");
    printf("num: %zu\n", num);
    printf("t_start: %lu\n", t_start);
    printf("t_end %lu\n", t_start + num);
    printf("enc_count: %zu\n", enc_count);
    printf("offset: %zu\n", offset);

    printf("Brute forcing: %zu enc count %zu\n", num, enc_count);

    // output
    size_t output_size = num * SHA256_DIGEST_SIZE * sizeof(uint8_t);
    printf("GPU RAM for random %.2f MB\n", output_size / 1024.0 / 1024.0);

    // Allocate device memory.
    uint8_t  *d_output;
    unsigned long long *d_found;
    unsigned long long *d_matches;
    unsigned long long *d_masks;

    if (cudaMalloc(&d_output, output_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_output\n");
        return 1;
    }
    if (cudaMalloc(&d_found, sizeof(unsigned long long )) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_found\n");
        return 1;
    }
    if (cudaMalloc(&d_matches, matches_size * sizeof(uint64_t)) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_matches\n");
        return 1;
    }
    if (cudaMalloc(&d_masks, matches_size * sizeof(uint64_t)) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_masks\n");
        return 1;
    }

    unsigned long long  zero = 0;
    cudaMemcpy(d_found, &zero, sizeof(unsigned long long), cudaMemcpyHostToDevice);

    // copy matches and masks
    cudaMemcpy(d_matches, matches, matches_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_masks, masks, matches_size * sizeof(uint64_t), cudaMemcpyHostToDevice);

    uint64_t start = get_time_in_nanosecond();


    // Launch kernel.
    int blockSize = 256;
    int gridSize = (num + blockSize - 1) / blockSize;

    printf("Using blockSize = %d, gridSize = %d\n", blockSize, gridSize);

    printf("Starting timestamp -> random calculation...: %zu nanoseconds\n", num);

    multihash_kernel_in_memory<<<gridSize, blockSize>>>(d_output, t_start, num);

    cudaDeviceSynchronize();
    uint64_t end1 = get_time_in_nanosecond();

    uint64_t end = get_time_in_nanosecond();


    int limit = num - enc_count - offset;

    printf("Total Time to translate timestamp to random %f ms\n", (end - start) / 1000000.0);
    // print speed per second
    printf("Speed: %f hashes per second\n", num / ((end1 - start) / 1000000000.0));

    printf("Limit: %d\n", limit);
    start = get_time_in_nanosecond();

    uint64_t start_enc = get_time_in_nanosecond();

    // set gridsize based on limit
    gridSize = (limit + blockSize - 1) / blockSize;

    uint64_t elapsed = 0;

    for (size_t i = 0; i < enc_count; i++)
    {
        // printf("Starting encryption and search at offset %d\n", i);
        encrypt_and_search_offset<<<gridSize, blockSize>>>(d_output, offset + i, d_found, d_masks, d_matches, matches_size, limit);
        // print error
        // cudaError_t err = cudaGetLastError();
        // if (err != cudaSuccess)
        // {
        //     fprintf(stderr, "Error: %s\n", cudaGetErrorString(err));
        //     return 1;
        // }
#define SKIP_CHECK 100
        if (i > 0 && (i % SKIP_CHECK) == 0)
        {
            uint64_t end_enc = get_time_in_nanosecond();
            printf("Enc Time (%zu): %f ms\n", i, (end_enc - start_enc) / 1000000.0);

            elapsed += (end_enc - start_enc);
            printf("%.2f  minutes elapsed, ", elapsed / 1000000000.0 / 60.0);
            //remaining
            double remaining = (enc_count - i) * ((end_enc - start_enc)/SKIP_CHECK);
            printf("%.2f  minutes remaining (%.2f hours). ", remaining / 1000000000.0 / 60.0, remaining / 1000000000.0 / 3600.0);

            start_enc = get_time_in_nanosecond();
            printf("Progress: %zu/%zu (testing: %zu)\n", i, enc_count, offset + i);
        
            cudaDeviceSynchronize();
            // //print error
            // err = cudaGetLastError();
            // if (err != cudaSuccess)
            // {
            //     fprintf(stderr, "Error0: %s\n", cudaGetErrorString(err));
            //     return 1;
            // }

            unsigned long long  found = 0;
            cudaMemcpy(&found, d_found, sizeof(unsigned long long ), cudaMemcpyDeviceToHost);
            // err = cudaGetLastError();
            // if (err != cudaSuccess)
            // {
            //     fprintf(stderr, "Error1: %s\n", cudaGetErrorString(err));
            //     return 1;
            // }
            if (found)
            {
                size_t t_offset, t_index, match_pos;
                decode_offset_and_index(found, &t_offset, &t_index, &match_pos);
                printf("Found at  offset=%zu ts = %zu + %zu config_file = %s match_index %zu, file : %s\n",  t_offset, t_start, t_index, filename, match_pos, 
                    matches_filename[match_pos]);
        

                printf("Found at offset %zu found = %llu ts = %zu file = %s, match_index = %zu file: %s\n", t_offset, found, t_start + t_index, filename, match_pos, 
                    matches_filename[match_pos]);
                //write to output.txt
                FILE *f = fopen("output.txt", "a");
                if (f == NULL)
                {
                    printf("Error opening file!\n");
                    exit(1);
                }
                fprintf(f, "Found at offset %zu found = %llu ts = %zu file = %s, match_index = %zu file: %s\n", t_offset, found, t_start + t_index, filename, match_pos, 
                    matches_filename[match_pos]);
                fclose(f);
                // reset for next
                cudaMemcpy(d_found, &zero, sizeof(unsigned long long ), cudaMemcpyHostToDevice);
                // err = cudaGetLastError();
                // if (err != cudaSuccess)
                // {
                //     fprintf(stderr, "Error2: %s\n", cudaGetErrorString(err));
                //     return 1;
                // }
            }
        
            //write checkpoint
            config["offset"] = offset + i;
            config["index"] = i;
            std::ofstream o(checkpoint);
            o << std::setw(4) << config << std::endl;            
        }
    }

    cudaDeviceSynchronize();
    // //print error
    // err = cudaGetLastError();
    // if (err != cudaSuccess)
    // {
    //     fprintf(stderr, "Error0: %s\n", cudaGetErrorString(err));
    //     return 1;
    // }

    unsigned long long found = 0;
    cudaMemcpy(&found, d_found, sizeof(unsigned long long), cudaMemcpyDeviceToHost);
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Error1: %s\n", cudaGetErrorString(err));
        return 1;
    }
    if (found)
    {
        size_t t_offset, t_index, match_pos;
        decode_offset_and_index(found, &t_offset, &t_index, &match_pos);
        printf("Found at  offset=%zu ts = %zu + %zu filename = %s\n",  t_offset, t_start, t_index, filename);

    }

    uint64_t end_enc = get_time_in_nanosecond();
    printf("Offset Enc Time: %f ms\n", (end_enc - start_enc) / 1000000.0);

    return 0;
}

int do_bruteforce(const char *filename)
{
    json config;

    std::string json_file = filename;

    std::string checkpoint = json_file + "checkpoint.json";

    std::ifstream f(filename);
    if (!f.is_open())
    {
        fprintf(stderr, "Error: Could not open config file %s\n", filename);
        return 1;
    }

    try
    {
        f >> config;
    }
    catch (json::parse_error &e)
    {
        fprintf(stderr, "Error parsing JSON: %s\n", e.what());
        return 1;
    }

    size_t num;
    uint64_t t_start;
    size_t enc_count;
    size_t offset;

    size_t matches_size = 0;
    uint64_t *matches = 0;
    uint64_t *masks = 0;

    try
    {
        t_start = config["start_timestamp"].get<uint64_t>(); // start T3

        num = config["count"].get<size_t>(); // stop at T3 + count ns

        offset = config["offset"].get<size_t>(); // we start at T3 + offset ns

        enc_count = config["brute_force_time_range"].get<size_t>(); // we stop at T3 + offset + enc_count ns

        // parse matches, and put it in array (match = plaintext^encrypted)
        if (config.contains("matches"))
        {
            matches_size = config["matches"].size();
            matches = (uint64_t *)malloc(matches_size * sizeof(uint64_t));
            masks = (uint64_t *)malloc(matches_size * sizeof(uint64_t));
            for (size_t i = 0; i < matches_size; i++)
            {
                uint64_t plaintext = std::stoull(config["matches"][i]["plaintext"].get<std::string>(), 0, 16);
                uint64_t encrypted = std::stoull(config["matches"][i]["encrypted"].get<std::string>(), 0, 16);
                uint64_t bitmask = std::stoull(config["matches"][i]["bitmask"].get<std::string>(), 0, 16);
                matches[i] = plaintext ^ encrypted;
                printf("Match %zu: %016lx\n", i, matches[i]);
                masks[i] = bitmask;
                printf("Mask %zu: %016lx\n", i, masks[i]);
            }
        }
    }
    catch (json::exception &e)
    {
        fprintf(stderr, "Error reading JSON values: %s\n", e.what());
        return 1;
    }

    printf("Configuration:\n");
    printf("num: %zu\n", num);
    printf("t_start: %lu\n", t_start);
    printf("enc_count: %zu\n", enc_count);
    printf("offset: %zu\n", offset);

    printf("Brute forcing: %zu enc count %zu\n", num, enc_count);
    size_t input_size = num * 19 * sizeof(uint8_t);
    printf("Input size: %.2f MB\n", input_size / 1024.0 / 1024.0);

    // Allocate host memory.
    uint8_t *h_input = (uint8_t *)malloc(input_size);

    // output
    size_t output_size = num * SHA256_DIGEST_SIZE * sizeof(uint8_t);
    printf("Output size: %.2f MB\n", output_size / 1024.0 / 1024.0);

    uint8_t *h_output = (uint8_t *)malloc(output_size);

    size_t enc_output_size = enc_count * TEST_ENCRYPT_BLOCK_SIZE * sizeof(uint8_t);

    uint8_t *h_output_enc = (uint8_t *)malloc(enc_output_size);

    uint64_t start_fill = get_time_in_nanosecond();

    fill_input(h_input, t_start, num); // GENERATE TS

    uint64_t end_fill = get_time_in_nanosecond();
    printf("Fill Time: %f ms\n", (end_fill - start_fill) / 1000000.0);

    // Allocate device memory.
    uint8_t *d_input, *d_output, *d_output_enc;
    int *d_found;
    unsigned long long *d_matches;
    unsigned long long *d_masks;

    if (cudaMalloc(&d_input, input_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_input\n");
        return 1;
    }
    if (cudaMalloc(&d_output, output_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_output\n");
        return 1;
    }
    if (cudaMalloc(&d_output_enc, enc_output_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_output_enc\n");
        return 1;
    }
    if (cudaMalloc(&d_found, sizeof(int)) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_found\n");
        return 1;
    }
    if (cudaMalloc(&d_matches, matches_size * sizeof(uint64_t)) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_matches\n");
        return 1;
    }
    if (cudaMalloc(&d_masks, matches_size * sizeof(uint64_t)) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_masks\n");
        return 1;
    }

    long zero = 0;
    cudaMemcpy(d_found, &zero, sizeof(int), cudaMemcpyHostToDevice);

    // copy matches and masks
    cudaMemcpy(d_matches, matches, matches_size * sizeof(uint64_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_masks, masks, matches_size * sizeof(uint64_t), cudaMemcpyHostToDevice);

    uint64_t start = get_time_in_nanosecond();

    cudaMemcpy(d_input, h_input, input_size, cudaMemcpyHostToDevice);

    // Launch kernel.
    int blockSize = 256;
    int gridSize = (num + blockSize - 1) / blockSize;

    printf("Using blockSize = %d, gridSize = %d\n", blockSize, gridSize);

    printf("Starting timestamp -> random calculation...\n");

    multihash_kernel<<<gridSize, blockSize>>>(d_input, d_output, num);
    cudaDeviceSynchronize();
    uint64_t end1 = get_time_in_nanosecond();
    cudaMemcpy(h_output, d_output, output_size, cudaMemcpyDeviceToHost);

    uint64_t end = get_time_in_nanosecond();

    // //print first hash
    printf("First hash: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", h_output[i]);
    }
    printf("\n");
    // //print 2nd hash
    printf("+offset hash: ");
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", h_output[SHA256_DIGEST_SIZE * offset + i]);
    }
    printf("\n");

    printf("Total Time: %f ms\n", (end - start) / 1000000.0);
    // print speed per second
    printf("Speed: %f hashes per second\n", num / ((end1 - start) / 1000000000.0));

    size_t limit = num - enc_count - offset;
    printf("Limit: %zu\n", limit);
    start = get_time_in_nanosecond();

    int gridSizeEnc = (enc_count + blockSize - 1) / blockSize;

    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, gpuIndex);

    int maxThreadsPerBlock = prop.maxThreadsPerBlock;      // Maximum allowed per block
    blockSize = maxThreadsPerBlock;                        // Dynamically set blockSize
    gridSizeEnc = (enc_count + blockSize - 1) / blockSize; // Ensure full coverage

    printf("Encryption Using blockSize = %d, gridSize = %d\n", blockSize, gridSizeEnc);

    uint64_t start_enc = get_time_in_nanosecond();

    for (size_t i = 0; i < limit; i++)
    {

        // launch test_kcipher2_kernel_single
        uint32_t *host_i32 = (uint32_t *)(h_output + i * 32);

        uint32_t k1 = host_i32[0];
        uint32_t k2 = host_i32[1];
        uint32_t k3 = host_i32[2];
        uint32_t k4 = host_i32[3];


        if (i > 0 && i % 10000 == 0)
        {
            uint64_t end_enc = get_time_in_nanosecond();
            printf("10000 ns Time: %f ms\n", (end_enc - start_enc) / 1000000.0);
            printf("Speed for 10000 ns: %f enc per second\n", 10000 / ((end_enc - start_enc) / 1000000000.0));
            start_enc = get_time_in_nanosecond();

            printf("Processing %zu: T3 = %lu\n", i, t_start + i);
            fflush(stdout);
            // printf("Current key: %08x %08x %08x %08x\n", k1, k2, k3, k4);
        }

        if ((i % 100000) == 0)
        {
            // create checkpoint
            // modify json with current time
            config["start_timestamp"] = t_start + i;
            std::ofstream o(checkpoint);
            o << std::setw(4) << config << std::endl;
        }

        encrypt_and_search<<<gridSizeEnc, blockSize>>>(d_output + (offset + i) * 32, d_output_enc, k1, k2, k3, k4, d_found, d_masks, d_matches, matches_size, enc_count);

        cudaDeviceSynchronize();

        // copy match
        int found;
        cudaMemcpy(&found, d_found, sizeof(int), cudaMemcpyDeviceToHost);
        if (found)
        {

            // only copy the large block if we found a match
            cudaMemcpy(h_output_enc, d_output_enc, enc_output_size, cudaMemcpyDeviceToHost);

            // reset found flag for next match
            cudaMemcpy(d_found, &zero, sizeof(int), cudaMemcpyHostToDevice);
            // reset d_output_enc
            cudaMemset(d_output_enc, 0, enc_output_size);

            uint64_t *host_i64 = (uint64_t *)(h_output_enc);
            for (size_t j = 0; j < enc_count; j++)
            {
                for (size_t k = 0; k < matches_size; k++)
                {
                    if ((*host_i64 & masks[k]) == matches[k])
                    {
                        printf("Found Match %zu target %zu T3 = %lu T4 =  %lu offset=%lu\n", k, j, t_start + i, (t_start + i) + offset + j, offset + j);
                        // open file and write to it
                        FILE *out = fopen("output.txt", "a");
                        if (out != NULL)
                        {
			    fprintf(out, "Found Match %zu target %zu T3 = %lu T4 =  %lu offset=%lu\n", k, j, t_start + i, (t_start + i) + offset + j, offset + j);			
                            fclose(out);
                        }
                    }
                }

                host_i64 += 4;
            }
        }
    }

    end = get_time_in_nanosecond();

    printf("Total Time: %f ms\n", (end - start) / 1000000.0);
    // print speed per second
    printf("Speed: %f enc per second\n", enc_count / ((end - start) / 1000000000.0));

    // Cleanup.
    cudaFree(d_input);
    cudaFree(d_output);
    free(h_input);
    free(h_output);
    return 0;
}

//this will leak fd, but we don't care
uint8_t  *load_random(const char *filename, size_t *size)
{
    //mmap the file
    int fd;
    struct stat sb;
    uint8_t *addr;
    fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        perror("open");
        return 0;
    }
    //get file size using stat
    if (fstat(fd, &sb) == -1)
    {
        close(fd);
        perror("fstat");
        return 0;
    }
    *size = sb.st_size;
    addr = (uint8_t *)mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED)
    {
        close(fd);
        perror("mmap");
        return 0;        
    }
    return addr;
}

uint8_t *hex_to_bytes(const char *search_hex)
{
    if (strlen(search_hex)!=32) {
        printf("Search hex must be 32 bytes hex characters\n");
        return 0;
    }

    uint8_t * search = (uint8_t *)malloc(16);

    //convert search_hex (32 hex character, no space) to search
    for (int i = 0; i < 16; i++)
    {
        char tmp[3];
        tmp[0] = search_hex[i * 2];
        tmp[1] = search_hex[i * 2 + 1];
        tmp[2] = 0;
        search[i] = strtol(tmp, NULL, 16);
    }

    printf("Searching: ");
    //hexdump to verify
    for (int i = 0; i < 16; i++)
    {
        printf("%02x", search[i]);
    }
    printf("\n");

    //for every 4 byte do: __builtin_bswap32
    uint32_t *search_i32 = (uint32_t *)search;
    for (int i = 0; i < 4; i++)
    {
        search_i32[i] = __builtin_bswap32(search_i32[i]);
    }
    return search;
}

int search_random(uint8_t  *addr, size_t size, const char *search_hex)
{
    if (!addr || !search_hex) {
        return -1;
    }

    uint8_t *search = hex_to_bytes(search_hex);
    if (!search) {
        return -1;
    }

    //now search the file using memmem
    void * pos = memmem(addr, size, search, 16);
    int found_pos = 1;
    if (pos ) {
        printf("Found at index %ld\n", ((uint8_t *)pos - addr)/16);
        found_pos = ((uint8_t *)pos - addr)/16;

    } else {
        printf("Not found\n");
    }
    return found_pos;
}

//hash computation in GPU, chacha8 in CPU
int  test_chacha8_speed(size_t num)
{
    printf("Test random + Chacha8 : %lu\n", num);
    size_t input_size = num * 19 * sizeof(uint8_t);
    printf("Input size: %.2f MB\n", input_size / 1024.0 / 1024.0);

    // Allocate host memory.
    uint8_t *h_input = (uint8_t *)malloc(input_size);

    uint64_t t_start = TEST_TIMESTAMP + 2000; // TEST:  0 is for chacha, +1000 for chacha_nonce

    // output
    size_t output_size = num * SHA256_DIGEST_SIZE * sizeof(uint8_t);
    printf("Output size: %.2f MB\n", output_size / 1024.0 / 1024.0);

    uint8_t *h_output = (uint8_t *)malloc(output_size);

    uint64_t start_fill = get_time_in_nanosecond();

    fill_input(h_input, t_start, num);
    uint64_t end_fill = get_time_in_nanosecond();
    printf("Fill Time: %f ms\n", (end_fill - start_fill) / 1000000.0);

    // Allocate device memory.
    uint8_t *d_input, *d_output;
    if (cudaMalloc(&d_input, input_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_input\n");
        return 1;
    }
    if (cudaMalloc(&d_output, output_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_output\n");
        return 1;
    }

    uint64_t start = get_time_in_nanosecond();

    cudaMemcpy(d_input, h_input, input_size, cudaMemcpyHostToDevice);

    int blockSize = 256;
    int gridSize = (num + blockSize - 1) / blockSize; // Ensure full coverage

    printf("Using blockSize = %d, gridSize = %d\n", blockSize, gridSize);

    printf("Starting timestamp -> random calculation...\n");
    fflush(stdout);

    multihash_kernel<<<gridSize, blockSize>>>(d_input, d_output, num);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Error: %s\n", cudaGetErrorString(err));
        return 1;
    }

    cudaDeviceSynchronize();
    uint64_t end1 = get_time_in_nanosecond();
    cudaMemcpy(h_output, d_output, output_size, cudaMemcpyDeviceToHost);

    uint64_t end = get_time_in_nanosecond();
    printf("Total Time: %f ms\n", (end - start) / 1000000.0);
    // print speed per second
    printf("Speed: %f hashes per second\n", num / ((end1 - start) / 1000000000.0));
    // Cleanup.
    cudaFree(d_input);
    cudaFree(d_output);
    uint8_t input[64];
    uint8_t output[64];
    memset(input, 0, 64);
    start = get_time_in_nanosecond();
    for (size_t i = 0;  i < num; i++) {
        uint8_t *seed = h_output + i * SHA256_DIGEST_SIZE;
        uint8_t *iv = h_output + i * SHA256_DIGEST_SIZE;
        chacha8_ctx ctx;
        chacha8_keysetup(&ctx, seed, iv);
        chacha8_get_keystream_oneblock(&ctx,  output);
        
    }
    end = get_time_in_nanosecond();
    printf("Enc Total Time: %f ms\n", (end - start) / 1000000.0);
    //speed
    printf("Speed: %f enc per second\n", num / ((end - start) / 1000000000.0));


    return 0;
}

void hexdump(const char *title, const uint8_t *data, size_t size)
{
    printf("%s: ", title);
    const uint8_t *p = data;
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", p[i]);
    }
    printf("\n");
}


int bruteforce_chacha(const char *filename)
{
    std::string json_file = filename;
    std::string checkpoint = json_file + "checkpoint.json";
    uint64_t t3_ts;
    uint64_t t3_t1_offset;
    uint64_t t1_t2_start_offset;
    uint64_t t1_t2_end_offset;
    uint64_t encrypted, plaintext, value;

    //parse JSON
    std::ifstream f(filename);
    if (!f.is_open())
    {
        fprintf(stderr, "Error: Could not open config file %s\n", filename);
        return 1;
    }
    json config;
    try
    {
        f >> config;
        t3_ts = config["t3_ts"].get<uint64_t>(); //start of kcipher2
        t3_t1_offset = config["t3_t1_offset"].get<uint64_t>(); //how far from T3 do we want to start our timestamp
        t1_t2_start_offset = config["t1_t2_start_offset"].get<uint64_t>(); //start offset to test for t1-t2
        t1_t2_end_offset = config["t1_t2_end_offset"].get<uint64_t>(); //end offset to test for t1-t2
        encrypted = std::stoull(config["encrypted"].get<std::string>(), 0, 16);
        printf("Encrypted: %016lx\n", encrypted);
        plaintext = std::stoull(config["plaintext"].get<std::string>(), 0, 16);
        printf("Plaintext: %016lx\n", plaintext);
        value = encrypted ^ plaintext;
        printf("Value: %016lx\n", value);
    }
    catch (json::parse_error &e)
    {
        fprintf(stderr, "Error parsing JSON: %s\n", e.what());
        return 1;
    }



    size_t num = t3_t1_offset + t1_t2_end_offset;

    size_t input_size = num * 19 * sizeof(uint8_t);
    printf("Input size: %.2f MB\n", input_size / 1024.0 / 1024.0);

    // Allocate host memory.
    uint8_t *h_input = (uint8_t *)malloc(input_size);

    uint64_t t_start = t3_ts - t3_t1_offset;
    printf("t_start: %lu\n", t_start);
    uint64_t t_end = t_start + num;
    printf("t_end: %lu\n", t_end);

    // output
    size_t output_size = num * SHA256_DIGEST_SIZE * sizeof(uint8_t);
    printf("Output size: %.2f MB\n", output_size / 1024.0 / 1024.0);

    uint8_t *h_output = (uint8_t *)malloc(output_size);

    uint64_t start_fill = get_time_in_nanosecond();

    fill_input(h_input, t_start, num);
    uint64_t end_fill = get_time_in_nanosecond();
    printf("Fill Time: %f ms\n", (end_fill - start_fill) / 1000000.0);

    // Allocate device memory.
    uint8_t *d_input, *d_output;
    if (cudaMalloc(&d_input, input_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_input\n");
        return 1;
    }
    if (cudaMalloc(&d_output, output_size) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_output\n");
        return 1;
    }

    uint64_t start = get_time_in_nanosecond();

    cudaMemcpy(d_input, h_input, input_size, cudaMemcpyHostToDevice);

    int blockSize = 256;
    int gridSize = (num + blockSize - 1) / blockSize; // Ensure full coverage

    printf("Using blockSize = %d, gridSize = %d\n", blockSize, gridSize);

    printf("Starting seed calculation...\n");
    fflush(stdout);

    multihash_kernel_noswap<<<gridSize, blockSize>>>(d_input, d_output, num);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess)
    {
        fprintf(stderr, "Error: %s\n", cudaGetErrorString(err));
        return 1;
    }

    cudaDeviceSynchronize();
    uint64_t end1 = get_time_in_nanosecond();
    cudaMemcpy(h_output, d_output, output_size, cudaMemcpyDeviceToHost);

    uint64_t end = get_time_in_nanosecond();
    printf("Total Time: %f ms\n", (end - start) / 1000000.0);
    // print speed per second
    printf("Speed: %f hashes per second\n", num / ((end1 - start) / 1000000000.0));
    // Cleanup.
    cudaFree(d_input);

    size_t num_loop = t3_t1_offset;

    blockSize = 256;
    gridSize = (num_loop + blockSize - 1) / blockSize; // Ensure full coverage

    unsigned long long *d_found;
    if (cudaMalloc(&d_found, sizeof(unsigned long long)) != cudaSuccess)
    {
        fprintf(stderr, "Error: cudaMalloc failed for d_found\n");
        return 1;
    }

    start = get_time_in_nanosecond();

    for (size_t offset = t1_t2_start_offset; offset < t1_t2_end_offset; offset++)
    {        
        size_t n = offset - t1_t2_start_offset;
        if ((n % 500)==0) {
            end1 = get_time_in_nanosecond();
            printf("Time: %f ms\n", (end1 - start) / 1000000.0);
            double offset_per_second = n / ((end1 - start) / 1000000000.0);
            printf("Speed: %f offsets per second\n", offset_per_second);
            printf("Processing offset %zu elapsed %f minutes\n", offset, (end1 - start) / 1000000000.0 / 60.0);
            //remaining
            double remaining = (t1_t2_end_offset - offset) / offset_per_second;
            printf("Remaining: %zu minutes\n", (size_t)(remaining / 60.0));
        }
#if 0
        printf("ts = %zu\n", t_start);
        printf("Tp Offset: %zu ts = %zu\n",  offset, t_start + offset);
        uint8_t output[64];
        uint64_t *val = (uint64_t *)output;
        for (size_t i = 0; i < num_loop; i++ ) { 
            uint8_t *seed = h_output + i * SHA256_DIGEST_SIZE;
            //hexdump("Seed", seed, 32);
            uint8_t *iv = h_output + (i + offset) * SHA256_DIGEST_SIZE;
            //hexdump("IV", iv, 16);
            chacha8_ctx ctx;
            chacha8_keysetup(&ctx, seed, iv);
            chacha8_get_keystream_oneblock(&ctx,  output);
            //hexdump output
            hexdump("Output", output, 64);
            if (*val == value) {
                printf("Found at time %zu offset = %zu\n", i, offset);
                //save to file output.txt
                FILE *out = fopen("output.txt", "a");
                if (out != NULL)
                {
                    fprintf(out, "Found at time %zu offset = %zu\n", i, offset);
                    fclose(out);
                }

                return 0;
            }
            //break;
        }
        //break;
#else 
        //test using GPU 
        
        chacha8_encrypt_and_match<<<gridSize, blockSize>>>(d_output, offset, d_found, value, num_loop);
        // //check for errors
        // cudaError_t err = cudaGetLastError();
        // if (err != cudaSuccess)
        // {
        //     fprintf(stderr, "Error: %s\n", cudaGetErrorString(err));
        //     return 1;
        // }
        //sync
        if (n % 1000 == 0) {
            cudaDeviceSynchronize();
            unsigned long long found = 0;
            cudaMemcpy(&found, d_found, sizeof(unsigned long long), cudaMemcpyDeviceToHost);
            if (found) {
                //        unsigned long long encoded_offset_and_index = (unsigned long long)offset << 32 | idx;
                size_t t_offset, t_index;
                t_offset = found >> 32;
                t_index = found & 0xffffffff;
                printf("Found at offset %zu index %zu\n", t_offset, t_index + t_start);
                //write to file
                FILE *out = fopen("output.txt", "a");
                if (out != NULL)
                {
                    fprintf(out, "Found at offset %zu index %zu\n", t_offset, t_index + t_start);
                    fclose(out);
                }
                return 1;
            }
        }
#endif
    }

    return 0;

}



int main(int argc, char *argv[])
{
    size_t num = 128 * 1000;

    int smCount;
    cudaDeviceGetAttribute(&smCount, cudaDevAttrMultiProcessorCount, gpuIndex);
    printf("SM count: %d\n", smCount);

    if (argc > 1)
    {
        if (strcmp(argv[1], "random") == 0) //test generate random from timestamp
        {
            if (argc > 2)
            {
                num = atoll(argv[2]);
            }

            return test_generate_random_only(num);
        }
        if (strcmp(argv[1], "random-gpu") == 0) //test generate random from timestamp, using GPU
        {
            if (argc > 2)
            {
                num = atoll(argv[2]);
            }

            return test_generate_random_only_in_gpu(num);
        }

        if (strcmp(argv[1], "saverandom") == 0)
        {
            uint64_t start_time = get_time_in_nanosecond();
            if (argc > 1)
            {
                start_time = atoll(argv[2]);
                char tmp[16];
                snprintf(tmp, sizeof(tmp), "%lu", start_time);
                if (strlen(tmp)<19) {
                    start_time = start_time * 1000000000;
                }

            }
            char filename[256];
            snprintf(filename, 256, "random_%lu.bin", start_time);

            return save_random(start_time, filename);
        }
        if (strcmp(argv[1], "search") == 0) {
            if (argc > 3) {
                const char *filename = argv[2];
                const char *search_hex = argv[3];
                size_t size;
                uint8_t *addr = load_random(filename, &size);
                if (addr) {
                    int res = search_random(addr, size, search_hex);
                    if (argc > 4) {
                        const char *search_hex2 = argv[4];
                        int res2 = search_random(addr, size, search_hex2);
                        printf("Diff: %d\n", res2-res);
                    }
                }
            } else {
                printf("usage: search random.bin 16_byte_hex_sequece_no_space\n");
            }
        }

        if (strcmp(argv[1], "enc") == 0) //test encryption only
        {
            if (argc > 2)
            {
                num = atoll(argv[2]);
            }
            return test_encryption_only(num);
        }

        if (strcmp(argv[1], "chacha8") == 0) //test chacha8 only
        {
            if (argc > 2)
            {
                num = atoll(argv[2]);
            }
            return test_chacha8_speed(num);
        }        

        if (strcmp(argv[1], "runchacha") == 0 || strcmp(argv[1], "runchacha8") == 0) //run chacha8 bruteforce
        {
            if (argc > 2)
            {                        
                if (argc > 3)
                {
                    gpuIndex = atoi(argv[3]);
                }

                int deviceCount;
                cudaGetDeviceCount(&deviceCount);

                if (gpuIndex < 0 || gpuIndex >= deviceCount)
                {
                    printf("Invalid GPU index %d\n", gpuIndex);
                    return EXIT_FAILURE;
                }
                cudaSetDevice(gpuIndex);
                printf("Using GPU %d\n", gpuIndex);

                return bruteforce_chacha(argv[2]);
            } else {
                printf("Usage: runchacha config.json\n");
            }
        }
        //main bruteforce loop
        if (strcmp(argv[1], "run") == 0 || strcmp(argv[1], "run2")==0  || strcmp(argv[1], "run3") == 0)
        {
            // read config from JSON file
            if (argc > 2)
            {
                if (argc > 3)
                {
                    gpuIndex = atoi(argv[3]);
                }

                int deviceCount;
                cudaGetDeviceCount(&deviceCount);

                if (gpuIndex < 0 || gpuIndex >= deviceCount)
                {
                    printf("Invalid GPU index %d\n", gpuIndex);
                    return EXIT_FAILURE;
                }
                cudaSetDevice(gpuIndex);
                printf("Using GPU %d\n", gpuIndex);

                if (strcmp(argv[1], "run") == 0)
                {
                    return do_bruteforce(argv[2]); //this is the slow method
                }
                else if (strcmp(argv[1], "run2") == 0)
                {
                    return do_bruteforce_new(argv[2]); //this is the faster method
                } else if (strcmp(argv[1], "run3") == 0) {
                    return do_bruteforce_offset(argv[2]); //this will read values from offset.txt instead of using ranges
                }
            }
            printf("Please specify the JSON config file\n");
        }
    }

    return 0;
}
