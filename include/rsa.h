#ifndef _MYRSA_H
#define _MYRSA_H

#include <iostream>
#include <gmp.h>
#include <vector>

class MYRSA {
private:
    mpz_t p, q, n, phi, e, d;
    gmp_randstate_t state;
    size_t block_size;

    // 检测素数
    bool is_prime(mpz_t num, int iterations = 25);

    // 生成素数
    void generate_prime(mpz_t prime, mp_bitcnt_t bits);

    // PKCS#5 填充相关函数
    void add_pkcs5_padding(const unsigned char* data, size_t data_len, mpz_t padded) const;

    bool remove_pkcs5_padding(const mpz_t decrypted, std::vector<unsigned char>& result) const;

public:
    // 构造函数
    MYRSA();

    // 析构函数
    ~MYRSA();

    // 生成密钥对
    void generate_keys(mp_bitcnt_t length = 2048);

    size_t get_block_size() const;

    void Encrypt_Block(mpz_t message, mpz_t result) const;

    void Decrypt_Block(const mpz_t &cipher, mpz_t result) const;

    // 加密解密函数

    void encrypt(unsigned char* message, size_t message_len, unsigned char* cipher, size_t &cipher_len) const;

    void decrypt(unsigned char* cipher, size_t cipher_len, unsigned char* message, size_t message_len) const;
};

#endif
