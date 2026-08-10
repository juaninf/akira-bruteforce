#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <nettle/yarrow.h>
#include "chacha8.h"
#include "test-ts.h"
#include "kcipher2.h"
#include <sys/mman.h>

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static void parse_hex(const char *hex, uint8_t *out, int len) {
    for (int i = 0; i < len; i++) {
        out[i] = (hexval(hex[2*i]) << 4) | hexval(hex[2*i+1]);
    }
}


uint32_t swap32(uint32_t x)
{
    return ((x & 0xff) << 24) | ((x & 0xff00) << 8) | ((x & 0xff0000) >> 8) | ((x & 0xff000000) >> 24);
}


void gen_key(uint64_t t, char *buffer, int size)
{
    struct yarrow256_ctx ctx;
    yarrow256_init(&ctx, 0, NULL);
    char seed[32];
    snprintf(seed, sizeof(seed), "%lld", t);

    yarrow256_seed(&ctx, strlen(seed), seed);
    yarrow256_random(&ctx, size, buffer);   

}

void hexdump(const char *title, const void *data, size_t size)
{
    printf("%s: ", title);
    const uint8_t *p = data;
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", p[i]);
    }
    printf("\n");
}



void compute_blocks(uint64_t filesize, 
    uint8_t percent,
    uint64_t *enc_block_size,
    uint64_t *part_size,
    uint64_t *encrypted_parts)
{
    int parts = 3;
    if ( percent > 49u )
        parts = 5;
    uint64_t enc_size = filesize * (uint64_t)percent / 100;
    *enc_block_size = enc_size / parts;
    *encrypted_parts = parts - 1;
    *part_size = (filesize - *enc_block_size * (*encrypted_parts)) / parts;  
}

void test_compute()
{
    uint64_t enc_block_size;
    uint64_t part_size;
    uint64_t encrypted_parts;
    compute_blocks(330, 15, &enc_block_size, &part_size, &encrypted_parts);
    printf("Enc block size: %lld\n", enc_block_size);
    printf("Part size: %lld\n", part_size);
    printf("Encrypted parts: %lld\n", encrypted_parts);
}

void decrypt_file_bykey(const char *filename, 
        uint8_t *chacha8_key, 
        uint8_t *cacha8_nonce,
        uint8_t *kcipher2_key,
        uint8_t *kcipher2_iv
    )
{

    //get file size
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("fopen");
        return;
    }
    fseek(fp, 0, SEEK_END);
    uint64_t filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fclose(fp);


    uint64_t enc_block_size;
    uint64_t part_size;
    uint64_t encrypted_parts;
#define PERCENT 15
    compute_blocks(filesize - 512, PERCENT, &enc_block_size, &part_size, &encrypted_parts);

    printf("Allocating: %zu bytes\n", enc_block_size);

    uint8_t *enc_block = (uint8_t *)malloc(128*1024);


    fp = fopen(filename, "r+b");
    if (!fp) {
        perror("fopen");
        free(enc_block);
        return;
    }

    struct chacha8_ctx chacha_ctx;

    chacha8_keysetup(&chacha_ctx, chacha8_key, cacha8_nonce);    


    uint32_t *kcipher2_key_ptr = (uint32_t *)kcipher2_key;
    //swap32
    for (int i = 0; i < 4; i++) {
        kcipher2_key_ptr[i] = swap32(kcipher2_key_ptr[i]);
    }

    uint32_t *kcipher2_iv_ptr = (uint32_t *)kcipher2_iv;
    //swap32
    for (int i = 0; i < 4; i++) {
        kcipher2_iv_ptr[i] = swap32(kcipher2_iv_ptr[i]);
    }

    kcipher2_init(kcipher2_key_ptr, kcipher2_iv_ptr);

    kcipher2_stream stream;
    init_kcipher2_stream(&stream, &State);

    size_t chacha_bytes = 0;
    int current_chacha_block = 0;

    for (int i = 0; encrypted_parts > i; ++i )
    {
      uint64_t offs = 0LL;
      uint64_t block_pos = part_size * i;
      while ( offs < enc_block_size )
      {
        size_t enc_size = 0xFFFFLL;
        if ( enc_block_size - offs <= 0xFFFF )
          enc_size = enc_block_size - offs;

        assert(enc_size < 128*1024);
        
        //seek to offs + block_pos
        fseek(fp, offs + block_pos, SEEK_SET);
        //read enc_size
        size_t bytesread = fread(enc_block, 1, enc_size, fp);
        if ( bytesread != enc_size )
        {
          perror("fread");
          free(enc_block);
          fclose(fp);
          return;
        }
        int current_enc = 0;
        if ( !offs || enc_block_size <= offs + bytesread )
            current_enc = 1;                        // kcipher2

        if ( current_enc ) {
            //kcipher2
            printf("Decrypting with kcipher2: %d at offs %zu\n",  bytesread, offs + block_pos);
            //hexdump("Encrypted kcipher2 block", enc_block, bytesread>32?32:bytesread);

            // // block size must be multiple of 8
            // int block_size = bytesread;
            // if (block_size % 8 != 0) {
            //     block_size = (block_size / 8 + 1) * 8;
            // }
            // kcipher2_encrypt(enc_zero_block, block_size, enc_tmp_block);        
            // for (int i = 0; i < bytesread; i++) {
            //     enc_block[i] ^= enc_tmp_block[i];
            // }
            kcipher2_xor_data(&stream, bytesread, enc_block);

            // //dump enc_tmp_block
            // hexdump("stream", enc_tmp_block, bytesread>32?32:bytesread);
            // //last 32 bytes
            // hexdump("stream (last 32 bytes)", enc_tmp_block + bytesread - 32,bytesread>32?32:bytesread);            


            //hexdump("decrypted kchiper2", enc_block, bytesread>32?32:bytesread);
            //last 32
            //hexdump("decrypted kchiper2 (last 32 bytes)", enc_block + bytesread - 32, bytesread>32?32:bytesread);
        } else {
            //hexdump("Encrypted block", enc_block, bytesread>32?32:bytesread);

            printf("Decrypting with chacha8 %zu offs=%zu\n", bytesread, offs);
            //chacha8
            
            int blocks = (bytesread + 63) / 64;
            chacha8_xor_keystream(&chacha_ctx, current_chacha_block, blocks, enc_block);
            current_chacha_block += blocks;

            //chacha8_xor_data(&chacha_stream, bytesread, enc_block);
            chacha_bytes += bytesread ;
            //hexdump("decrypted chacha", enc_block, bytesread<32?bytesread:32);
            //dump last 32 bytes
            //hexdump("decrypted chacha (last 32 bytes)", enc_block + bytesread - 32, bytesread>32?32:bytesread);

        }
        //seek and write back
        fseek(fp, offs + block_pos, SEEK_SET);
        fwrite(enc_block, 1, bytesread, fp);
        offs += bytesread;

      }  
    }  
    //truncate last 512 bytes
    ftruncate(fileno(fp), filesize - 512);
    fclose(fp);
    free(enc_block);
    printf("Decryption done\n"); 
    //rename, removing .akira from end of file
    char newname[256];
    snprintf(newname, sizeof(newname), "%s", filename);
    if (strstr(newname, ".akira")) {
        newname[strlen(newname) - 6] = 0;
        rename(filename, newname);
    }    
    


#if 0
    struct chacha8_ctx chacha_ctx;
    chacha8_keysetup(&chacha_ctx, chacha8_key, cacha8_nonce);
    //dump keystream hex
    printf("Chacha 20 state: ");
    uint8_t *state = (uint8_t *)chacha_ctx.input;
    for (int i = 0; i < 64; i++) {
        printf("%02x ", state[i]);
    }
    printf("\n");
    uint8_t test_data[256];
    uint8_t test_data_out[256];
    memset(test_data, 0, sizeof(test_data));
    memset(test_data_out, 0, sizeof(test_data_out));

    chacha8_get_keystream(&chacha_ctx, 0, 5, test_data);
    hexdump("Chacha8 Stream", test_data, sizeof(test_data));

    uint32_t *kcipher2_key_ptr = (uint32_t *)kcipher2_key;
    //swap32
    for (int i = 0; i < 4; i++) {
        kcipher2_key_ptr[i] = swap32(kcipher2_key_ptr[i]);
    }

    uint32_t *kcipher2_iv_ptr = (uint32_t *)kcipher2_iv;
    //swap32
    for (int i = 0; i < 4; i++) {
        kcipher2_iv_ptr[i] = swap32(kcipher2_iv_ptr[i]);
    }

    //for testing zero vectors
//     memset(kcipher2_key_ptr, 0, 16);
//     memset(kcipher2_iv_ptr, 0, 16);
    
    printf("KEY as int32: ");
    for (int i = 0; i < 4; i++) {
        printf("%08x ", kcipher2_key_ptr[i]);
    }
    printf("\n");
    printf("IV as int32: ");
    for (int i = 0; i < 4; i++) {
        printf("%08x ", kcipher2_iv_ptr[i]);
    }
    printf("\n");

    kcipher2_init(kcipher2_key_ptr, kcipher2_iv_ptr);


/*
 *
typedef struct
{
	unsigned int  A[5];
	unsigned int  B[11];
	unsigned int  L1, R1, L2, R2;

} kcipher2_state;

*/
    	//DUMP all the state
	// printf("kcipher2_state:\n");
	// printf("A[5]:\n");
	// for (int i = 0; i < 5; i++) {
	// 	printf("%08x ", State.A[i]);
	// }
	// printf("\n");
	// printf("B[11]:\n");
	// for (int i = 0; i < 11; i++) {
	// 	printf("%08x ", State.B[i]);
	// }
	// printf("\n");
	// printf("L1: %08x\n", State.L1);
	// printf("R1: %08x\n", State.R1);
	// printf("L2: %08x\n", State.L2);
	// printf("R2: %08x\n", State.R2);
	// printf("\n");

    memset(test_data, 0, sizeof(test_data));
    memset(test_data_out, 0, sizeof(test_data_out));
    kcipher2_encrypt(test_data, sizeof(test_data), test_data_out);
    hexdump("Kcipher2 Stream", test_data_out, sizeof(test_data_out));
#endif    
}


void decrypt_file(const char *filename, uint64_t t1, uint64_t t2, uint64_t t3, uint64_t t4)
{    
    uint8_t chacha8_key[32];
    uint8_t cacha8_nonce[16];
    uint8_t kcipher2_key[16];
    uint8_t kcipher2_iv[16];

    printf("T1 = %lld\n", t1);
    gen_key(t1, chacha8_key, 32);
    hexdump("chacha8_k8", chacha8_key, 32);
    printf("T2 = %lld\n", t2);
    gen_key(t2, cacha8_nonce, 16);
    hexdump("chacha8_nonce", cacha8_nonce, 16);
    printf("T3 = %lld\n", t3);
    gen_key(t3, kcipher2_key, 16);
    hexdump("kcipher2_key  ", kcipher2_key, 16);
    printf("T4 = %lld\n", t4);
    gen_key(t4, kcipher2_iv, 16);
    hexdump("kcipher2_iv ", kcipher2_iv, 16);

    decrypt_file_bykey(filename, chacha8_key, cacha8_nonce, kcipher2_key, kcipher2_iv);

}


int main(int argc, char *argv[])
{
    //test_compute();

    // uint8_t chacha8_key[32];
    // uint8_t cacha8_nonce[16];
    // uint8_t kcipher2_key[16];
    // uint8_t kcipher2_iv[16];
    // memset(chacha8_key, 0, sizeof(chacha8_key));
    // memset(cacha8_nonce, 0, sizeof(cacha8_nonce));
    // memset(kcipher2_key, 0, sizeof(kcipher2_key));
    // memset(kcipher2_iv, 0, sizeof(kcipher2_iv));

    // printf("Test zero input: ");
    // decrypt_file_bykey("test-zero/mytest.akira", chacha8_key, cacha8_nonce, kcipher2_key, kcipher2_iv);

    if (argc > 2 && strcmp(argv[1], "bykey") == 0) {
        // Usage: decrypt bykey <filename> <chacha8_key_hex> <chacha8_nonce_hex> <kcipher2_key_hex> <kcipher2_iv_hex>
        if (argc < 7) {
            printf("Usage: %s bykey <filename> <chacha8_key_64hex> <chacha8_nonce_32hex> <kcipher2_key_32hex> <kcipher2_iv_32hex>\n", argv[0]);
            return 1;
        }
        uint8_t chacha8_key[32];
        uint8_t chacha8_nonce[16];
        uint8_t kcipher2_key[16];
        uint8_t kcipher2_iv[16];
        parse_hex(argv[3], chacha8_key, 32);
        parse_hex(argv[4], chacha8_nonce, 16);
        parse_hex(argv[5], kcipher2_key, 16);
        parse_hex(argv[6], kcipher2_iv, 16);
        printf("chacha8_key:   "); hexdump("", chacha8_key, 32);
        printf("chacha8_nonce: "); hexdump("", chacha8_nonce, 16);
        printf("kcipher2_key:  "); hexdump("", kcipher2_key, 16);
        printf("kcipher2_iv:   "); hexdump("", kcipher2_iv, 16);
        decrypt_file_bykey(argv[2], chacha8_key, chacha8_nonce, kcipher2_key, kcipher2_iv);
    } else if (argc > 5) {
        uint64_t t1 = atoll(argv[2]);
        uint64_t t2 = atoll(argv[3]);
        uint64_t t3 = atoll(argv[4]);
        uint64_t t4 = atoll(argv[5]);
        decrypt_file(argv[1], t1, t2, t3, t4);
    } else {
        printf("Usage: %s <filename> <t1> <t2> <t3> <t4>\n", argv[0]);
        printf("   or: %s bykey <filename> <chacha8_key_64hex> <chacha8_nonce_32hex> <kcipher2_key_32hex> <kcipher2_iv_32hex>\n", argv[0]);
    }


    // uint64_t time_start = TEST_TIMESTAMP;
    // decrypt_file("test-zero/mytest.akira", time_start, time_start + 1000, time_start +2000 , time_start + 3000);
    // decrypt_file("test-zero/mytest.akira", time_start, time_start + 1000, time_start +2000 , time_start + 3001);
    // decrypt_file("test-zero/mytest.akira", time_start, time_start + 1000, time_start +2000 , time_start + 3999);
    // decrypt_file("test-zero/mytest.akira", time_start, time_start + 1000, time_start +2001 , time_start + 3001);

    return 0;
}
