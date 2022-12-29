#ifndef SCRYPT_H
#define SCRYPT_H

void scrypt_1024_1_1_256(const char* input, char* output);
void scrypt_1024_1_1_256_sp(const char* input, char* output, char* scratchpad);
const int scrypt_scratchpad_size = 131583;

#endif