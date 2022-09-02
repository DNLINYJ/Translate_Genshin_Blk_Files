#pragma once
#include <iostream>
void mhy0_header_scramble(uint8_t* input, uint64_t limit, uint8_t* input2, uint64_t chunk_size);
void key_scramble1(uint8_t* key);
void key_scramble2(uint8_t* key);
void create_decrypt_vector(uint8_t* key, uint8_t* encrypted_data, uint64_t encrypted_size, uint8_t* output, uint64_t output_size);