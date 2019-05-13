#pragma once
#include "Ristretto\ristretto-donna.h"

#if defined(__cplusplus)
extern "C" {
#endif
void print_uchar32(unsigned char uchar[32]);
int test_curve25519_expand_random_field_element();
int test_curve25519_expand_basepoint();
int test_curve25519_expand_identity();
int test_ge25519_unpack_pack();
int test_invsqrt_random_field_element();
int test_ristretto_decode_random_invalid_point();
int test_ristretto_decode_basepoint();
int test_ristretto_encode_small_multiples_of_basepoint();
int test_ristretto_encode_identity();
int test_ristretto_encode_basepoint();
int test_uint8_32_ct_eq();
int test_ristretto_ct_eq();
int test_ristretto();
#if defined(__cplusplus)
}
#endif