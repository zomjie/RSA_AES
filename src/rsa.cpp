#include "../include/rsa.h"
#include <iostream>
#include <time.h>
#include <cstring>
#include <iomanip>

bool MYRSA::is_prime(mpz_t num, int iterations) {
    return mpz_probab_prime_p(num, iterations) > 0;
}

void MYRSA::generate_prime(mpz_t prime, mp_bitcnt_t bits) {
    mpz_t temp;
    mpz_init(temp);
    
    mpz_rrandomb(temp, state, bits);
    mpz_nextprime(prime, temp);

    if(!is_prime(prime)){
        std::cerr<<"Error while gnerating a prime"<<std::endl;
    }
    
    mpz_clear(temp);
}

MYRSA::MYRSA() {
    mpz_init(p);
    mpz_init(q);
    mpz_init(n);
    mpz_init(phi);
    mpz_init(e);
    mpz_init(d);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    block_size = 0;
}

MYRSA::~MYRSA() {
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(phi);
    mpz_clear(e);
    mpz_clear(d);
    gmp_randclear(state);
}

void MYRSA::generate_keys(mp_bitcnt_t length) {
    generate_prime(p, length/2);
    generate_prime(q, length/2);

    if(!is_prime(p) && !is_prime(q)) {
        std::cerr << "Keys generation failed" << std::endl;
    }

    mpz_mul(n, p, q);

    //calculate block_size
    size_t key_bytes = (mpz_sizeinbase(n, 2) + 7) / 8;
    block_size = key_bytes - 1;

    mpz_t p_minus_1, q_minus_1;
    mpz_init(p_minus_1);
    mpz_init(q_minus_1);
    mpz_sub_ui(p_minus_1, p, 1);
    mpz_sub_ui(q_minus_1, q, 1);
    mpz_mul(phi, p_minus_1, q_minus_1);

    mpz_set_ui(e, 65537);
    mpz_invert(d, e, phi);

    mpz_clear(p_minus_1);
    mpz_clear(q_minus_1);
	
//	std::cout << "p = 0x";  // 添加0x前缀表示16进制
//	mpz_out_str(stdout, 16, p);
//	std::cout << "\nq = 0x";
//	mpz_out_str(stdout, 16, q);
//	std::cout << "\nn = 0x";
//	mpz_out_str(stdout, 16, n);
//	std::cout << "\ne = 0x";
//	mpz_out_str(stdout, 16, e);
//	std::cout << "\nd = 0x";
//	mpz_out_str(stdout, 16, d);
//	std::cout << std::endl;
}

size_t MYRSA::get_block_size() const{
    return block_size;
}

void MYRSA::Encrypt_Block(mpz_t message, mpz_t result) const{
    if(mpz_sizeinbase(message, 2) > mpz_sizeinbase(n, 2)){
        std::cerr<<"Error while encrypt a block, message larger than n"<<std::endl;
    }
    mpz_powm(result, message, e, n);
}

void MYRSA::Decrypt_Block(const mpz_t& cipher, mpz_t result) const{
   mpz_powm(result, cipher, d, n); 
}

void MYRSA::encrypt(unsigned char* message, size_t message_len, unsigned char* cipher, size_t &cipher_len) const {
    size_t block_size = get_block_size();
    
    if(message_len > block_size){
        std::cerr<<"Message to long for RSA"<<std::endl;
    }

    mpz_t message_mpz, cipher_mpz;
    mpz_init(message_mpz);
    mpz_init(cipher_mpz);

    mpz_import(message_mpz, message_len, 1, 1, 0, 0, message);
    Encrypt_Block(message_mpz, cipher_mpz);
    
    cipher_len = mpz_sizeinbase(cipher_mpz, 256);

    //std::cout<<"Cipher len: 0x"<<cipher_len<<std::endl;

    mpz_export(cipher, NULL, 1, 1, 0, 0, cipher_mpz);

    mpz_clear(cipher_mpz);
    mpz_clear(message_mpz);
}

void MYRSA::decrypt(unsigned char* cipher, size_t cipher_len, unsigned char* message, size_t message_len) const {
    mpz_t cipher_mpz, message_mpz;
    mpz_init(cipher_mpz);
    mpz_init(message_mpz);

    mpz_import(cipher_mpz, cipher_len, 1, 1, 0, 0, cipher);
    Decrypt_Block(cipher_mpz, message_mpz);

    size_t offset = message_len - mpz_sizeinbase(message_mpz, 256);
    mpz_export(message + offset, NULL, 1, 1, 0, 0, message_mpz);

    mpz_clear(cipher_mpz);
    mpz_clear(message_mpz);

}
