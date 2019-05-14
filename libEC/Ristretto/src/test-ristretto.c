// This file is part of ristretto-donna.
// Copyright (c) 2019 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

#define RISTRETTO_DONNA_PRIVATE

#include <stdint.h>
#include <stdio.h>

#include "ristretto-donna.h"

/// Random element a of GF(2^255-19), from Sage
/// a = 10703145068883540813293858232352184442332212228051251926706380353716438957572
const uint8_t A_BYTES[32] = {
  0x04, 0xfe, 0xdf, 0x98, 0xa7, 0xfa, 0x0a, 0x68,
  0x84, 0x92, 0xbd, 0x59, 0x08, 0x07, 0xa7, 0x03,
  0x9e, 0xd1, 0xf6, 0xf2, 0xe1, 0xd9, 0xe2, 0xa4,
  0xa4, 0x51, 0x47, 0x36, 0xf3, 0xc3, 0xa9, 0x17
};

/// Byte representation of a**2
const uint8_t ASQ_BYTES[32] = {
  0x75, 0x97, 0x24, 0x9e, 0xe6, 0x06, 0xfe, 0xab,
  0x24, 0x04, 0x56, 0x68, 0x07, 0x91, 0x2d, 0x5d,
  0x0b, 0x0f, 0x3f, 0x1c, 0xb2, 0x6e, 0xf2, 0xe2,
  0x63, 0x9c, 0x12, 0xba, 0x73, 0x0b, 0xe3, 0x62
};

/// Byte representation of 1/a
const uint8_t AINV_BYTES[32] = {
  0x96, 0x1b, 0xcd, 0x8d, 0x4d, 0x5e, 0xa2, 0x3a,
  0xe9, 0x36, 0x37, 0x93, 0xdb, 0x7b, 0x4d, 0x70,
  0xb8, 0x0d, 0xc0, 0x55, 0xd0, 0x4c, 0x1d, 0x7b,
  0x90, 0x71, 0xd8, 0xe9, 0xb6, 0x18, 0xe6, 0x30
};

/// Byte representation of a^((p-5)/8)
const uint8_t AP58_BYTES[32] = {
  0x6a, 0x4f, 0x24, 0x89, 0x1f, 0x57, 0x60, 0x36,
  0xd0, 0xbe, 0x12, 0x3c, 0x8f, 0xf5, 0xb1, 0x59,
  0xe0, 0xf0, 0xb8, 0x1b, 0x20, 0xd2, 0xb5, 0x1f,
  0x15, 0x21, 0xf9, 0xe3, 0xe1, 0x61, 0x21, 0x55
};

const unsigned char IDENTITY[32] = {0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0};

void print_uchar32(unsigned char uchar[32])
{
  unsigned char i;

  for (i=0; i<32; i++) {
#ifdef DEBUGGING
    printf("%02x, ", uchar[i]);
#endif
  }
#ifdef DEBUGGING
  printf("\n");
#endif
}

int test_curve25519_expand_random_field_element()
{
  bignum25519 a;
  unsigned char a_bytes[32]; // discard the const qualifier
  unsigned char b[32];

  printf("expanding and contracting random field element: ");

  memcpy(a_bytes, A_BYTES, 32);

  curve25519_expand(a, a_bytes);
  curve25519_contract(b, a);

  if (!uint8_32_ct_eq(A_BYTES, b)) {
    printf("FAIL\n");
    PRINT("a="); print_uchar32(a_bytes);
    PRINT("b="); print_uchar32(b);
    return 0;
  } else {
    printf("OKAY\n");
    return 1;
  }
}

int test_curve25519_expand_basepoint()
{
  bignum25519 a;
  unsigned char b[32];

  printf("expanding and contracting basepoint: ");

  curve25519_expand(a, RISTRETTO_BASEPOINT_COMPRESSED);
  curve25519_contract(b, a);

  if (!uint8_32_ct_eq(RISTRETTO_BASEPOINT_COMPRESSED, b)) {
    printf("FAIL\n");
    PRINT("a="); print_uchar32(RISTRETTO_BASEPOINT_COMPRESSED);
    PRINT("b="); print_uchar32(b);
    return 0;
  } else {
    printf("OKAY\n");
    return 1;
  }
}

int test_curve25519_expand_identity()
{
  bignum25519 a;
  unsigned char b[32];

  printf("test expanding and contracting additive identity: ");

  curve25519_expand(a, IDENTITY);
  curve25519_contract(b, a);

  if (!uint8_32_ct_eq(IDENTITY, b)) {
    printf("FAIL\n");
    PRINT("a="); print_uchar32((unsigned char*)IDENTITY);
    PRINT("b="); print_uchar32(b);
    return 0;
  } else {
    printf("OKAY\n");
    return 1;
  }
}

int test_ge25519_unpack_pack()
{
  ge25519 a;
  unsigned char b[32];
  int result;

  printf("test unpacking and packing a group element: ");

  result = ge25519_unpack_negative_vartime(&a, IDENTITY);
  ge25519_pack_without_parity(b, &a);

  if (!uint8_32_ct_eq(b, IDENTITY)) {
    result &= 0;
  }

  if (result != 1) {
    printf("FAIL\n");
    PRINT("a="); print_uchar32((unsigned char*)IDENTITY);
    PRINT("b="); print_uchar32(b);
  } else {
    printf("OKAY\n");
  }

  return result;
}

int test_invsqrt_random_field_element()
{
  bignum25519 check, v, v_invsqrt;
  uint8_t result;

  // Use v = decode(ASQ_BYTES) so it's guaranteed to be square

  //curve25519_expand(v, ASQ_BYTES);
  curve25519_copy(v, one);
  result = curve25519_invsqrt(v_invsqrt, v);

  printf("invsqrt test: ");
  if (result == 1) {
    // expect v_invsqrt = sqrt(1/v)
    // check = 1/v
    curve25519_square(check, v_invsqrt);
    // check = 1
    curve25519_mul(check, check, v);
    // assert check == 1
    if (bignum25519_ct_eq(check, one) == 1) {
      printf("OKAY invsqrt computed correctly with tweak=1\n");
      return 1;
    } else {
      printf("FAIL invsqrt not computed correctly with tweak=1\n");
      PRINT("v_invsqrt = "); fe_print(v_invsqrt);
      return 0;
    }
  } else if (result == 0) {
    // expect v_invsqrt = sqrt(i/v)
    // check = i/v
    curve25519_square(check, v_invsqrt);
    // check = i
    curve25519_mul(check, check, v);
    // assert check == i
    if (bignum25519_ct_eq(check, SQRT_M1) == 1) {
      printf("OKAY invsqrt computed correctly with tweak=i\n");
      return 1;
    } else {
      printf("FAIL invsqrt not computed correctly with tweak=i\n");
      return 0;
    }
  } else {
    printf("FAIL invsqrt did not return 0 or 1\n");
    return 0;
  }

}

int test_ristretto_decode_random_invalid_point()
{
  ristretto_point_t point;
  uint8_t result;

  // This field element doesn't represent a valid point…
  result = ristretto_decode(&point, A_BYTES);

  printf("decoding random invalid point: ");
  if (result != 0) { // …and thus we want the decoding to fail.
    printf("FAIL result=%d\n", result);
    return 1;
  } else {
    printf("OKAY\n");
    return 0;
  }
}

int test_ristretto_decode_basepoint()
{
  ristretto_point_t point;
  uint8_t result;

  result = ristretto_decode(&point, RISTRETTO_BASEPOINT_COMPRESSED);

  printf("decoding basepoint: ");
  if (result != 1) {
    printf("FAIL result=%d\n", result);
  } else {
    printf("OKAY\n");
  }

  return (int)result;
}

int test_ristretto_encode_small_multiples_of_basepoint()
{
  uint8_t result = 1;
  ristretto_point_t P, B;
  unsigned char i;
  unsigned char encoded[32];
  unsigned char encodings_of_small_multiples[16][32] = {
    // This is the identity
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    // This is the basepoint
    {0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
     0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76},
    // These are small multiples of the basepoint
    {0x6a, 0x49, 0x32, 0x10, 0xf7, 0x49, 0x9c, 0xd1, 0x7f, 0xec, 0xb5, 0x10, 0xae, 0x0c, 0xea, 0x23,
     0xa1, 0x10, 0xe8, 0xd5, 0xb9, 0x01, 0xf8, 0xac, 0xad, 0xd3, 0x09, 0x5c, 0x73, 0xa3, 0xb9, 0x19},
    {0x94, 0x74, 0x1f, 0x5d, 0x5d, 0x52, 0x75, 0x5e, 0xce, 0x4f, 0x23, 0xf0, 0x44, 0xee, 0x27, 0xd5,
     0xd1, 0xea, 0x1e, 0x2b, 0xd1, 0x96, 0xb4, 0x62, 0x16, 0x6b, 0x16, 0x15, 0x2a, 0x9d, 0x02, 0x59},
    {0xda, 0x80, 0x86, 0x27, 0x73, 0x35, 0x8b, 0x46, 0x6f, 0xfa, 0xdf, 0xe0, 0xb3, 0x29, 0x3a, 0xb3,
     0xd9, 0xfd, 0x53, 0xc5, 0xea, 0x6c, 0x95, 0x53, 0x58, 0xf5, 0x68, 0x32, 0x2d, 0xaf, 0x6a, 0x57},
    {0xe8, 0x82, 0xb1, 0x31, 0x01, 0x6b, 0x52, 0xc1, 0xd3, 0x33, 0x70, 0x80, 0x18, 0x7c, 0xf7, 0x68,
     0x42, 0x3e, 0xfc, 0xcb, 0xb5, 0x17, 0xbb, 0x49, 0x5a, 0xb8, 0x12, 0xc4, 0x16, 0x0f, 0xf4, 0x4e},
    {0xf6, 0x47, 0x46, 0xd3, 0xc9, 0x2b, 0x13, 0x05, 0x0e, 0xd8, 0xd8, 0x02, 0x36, 0xa7, 0xf0, 0x00,
     0x7c, 0x3b, 0x3f, 0x96, 0x2f, 0x5b, 0xa7, 0x93, 0xd1, 0x9a, 0x60, 0x1e, 0xbb, 0x1d, 0xf4, 0x03},
    {0x44, 0xf5, 0x35, 0x20, 0x92, 0x6e, 0xc8, 0x1f, 0xbd, 0x5a, 0x38, 0x78, 0x45, 0xbe, 0xb7, 0xdf,
     0x85, 0xa9, 0x6a, 0x24, 0xec, 0xe1, 0x87, 0x38, 0xbd, 0xcf, 0xa6, 0xa7, 0x82, 0x2a, 0x17, 0x6d},
    {0x90, 0x32, 0x93, 0xd8, 0xf2, 0x28, 0x7e, 0xbe, 0x10, 0xe2, 0x37, 0x4d, 0xc1, 0xa5, 0x3e, 0x0b,
     0xc8, 0x87, 0xe5, 0x92, 0x69, 0x9f, 0x02, 0xd0, 0x77, 0xd5, 0x26, 0x3c, 0xdd, 0x55, 0x60, 0x1c},
    {0x02, 0x62, 0x2a, 0xce, 0x8f, 0x73, 0x03, 0xa3, 0x1c, 0xaf, 0xc6, 0x3f, 0x8f, 0xc4, 0x8f, 0xdc,
     0x16, 0xe1, 0xc8, 0xc8, 0xd2, 0x34, 0xb2, 0xf0, 0xd6, 0x68, 0x52, 0x82, 0xa9, 0x07, 0x60, 0x31},
    {0x20, 0x70, 0x6f, 0xd7, 0x88, 0xb2, 0x72, 0x0a, 0x1e, 0xd2, 0xa5, 0xda, 0xd4, 0x95, 0x2b, 0x01,
     0xf4, 0x13, 0xbc, 0xf0, 0xe7, 0x56, 0x4d, 0xe8, 0xcd, 0xc8, 0x16, 0x68, 0x9e, 0x2d, 0xb9, 0x5f},
    {0xbc, 0xe8, 0x3f, 0x8b, 0xa5, 0xdd, 0x2f, 0xa5, 0x72, 0x86, 0x4c, 0x24, 0xba, 0x18, 0x10, 0xf9,
     0x52, 0x2b, 0xc6, 0x00, 0x4a, 0xfe, 0x95, 0x87, 0x7a, 0xc7, 0x32, 0x41, 0xca, 0xfd, 0xab, 0x42},
    {0xe4, 0x54, 0x9e, 0xe1, 0x6b, 0x9a, 0xa0, 0x30, 0x99, 0xca, 0x20, 0x8c, 0x67, 0xad, 0xaf, 0xca,
     0xfa, 0x4c, 0x3f, 0x3e, 0x4e, 0x53, 0x03, 0xde, 0x60, 0x26, 0xe3, 0xca, 0x8f, 0xf8, 0x44, 0x60},
    {0xaa, 0x52, 0xe0, 0x00, 0xdf, 0x2e, 0x16, 0xf5, 0x5f, 0xb1, 0x03, 0x2f, 0xc3, 0x3b, 0xc4, 0x27,
     0x42, 0xda, 0xd6, 0xbd, 0x5a, 0x8f, 0xc0, 0xbe, 0x01, 0x67, 0x43, 0x6c, 0x59, 0x48, 0x50, 0x1f},
    {0x46, 0x37, 0x6b, 0x80, 0xf4, 0x09, 0xb2, 0x9d, 0xc2, 0xb5, 0xf6, 0xf0, 0xc5, 0x25, 0x91, 0x99,
     0x08, 0x96, 0xe5, 0x71, 0x6f, 0x41, 0x47, 0x7c, 0xd3, 0x00, 0x85, 0xab, 0x7f, 0x10, 0x30, 0x1e},
    {0xe0, 0xc4, 0x18, 0xf7, 0xc8, 0xd9, 0xc4, 0xcd, 0xd7, 0x39, 0x5b, 0x93, 0xea, 0x12, 0x4f, 0x3a,
     0xd9, 0x90, 0x21, 0xbb, 0x68, 0x1d, 0xfc, 0x33, 0x02, 0xa9, 0xd9, 0x9a, 0x2e, 0x53, 0xe6, 0x4e},
  };

  printf("encoding small multiples of basepoint:\n");

  ge25519_unpack_negative_vartime(&P.point, IDENTITY);
  ge25519_unpack_negative_vartime(&B.point, RISTRETTO_BASEPOINT_COMPRESSED);

  for (i=1; i<16; i++) {
    ristretto_encode(encoded, (const ristretto_point_t*)&P);

    if (!uint8_32_ct_eq(encoded, encodings_of_small_multiples[i])) {
      printf("  - FAIL small multiple #%d failed to encode correctly\n", i);
      PRINT("    original = ");
      print_uchar32(encodings_of_small_multiples[i]);
      PRINT("    encoded = ");
      print_uchar32(encoded);
      result &= 0;
    }

    ge25519_add(&P.point, &P.point, (const ge25519*)&B.point); // add another multiple of the basepoint
  }

  return (int)result;
}

int test_ristretto_encode_identity()
{
  ristretto_point_t point;
  unsigned char bytes[32];
  unsigned char i;
  uint8_t result = 1;

  printf("test ristretto encode identity: ");

  ristretto_decode(&point, IDENTITY);
  ristretto_encode(bytes, &point);

  for (i=0; i<32; i++) {
    if (bytes[i] != IDENTITY[i]) {
      PRINT("byte %d did not match: original=%u encoded=%u",
            i, IDENTITY[i], bytes[i]);
      result = 0;
    }
  }

  if (result != 1) {
    printf("FAIL\n");
  } else {
    printf("OKAY\n");
  }

  return (int)result;
}

int test_ristretto_encode_basepoint()
{
  ristretto_point_t point;
  unsigned char bytes[32];
  unsigned char i;
  uint8_t result = 1;

  printf("test ristretto encode basepoint: ");

  ristretto_decode(&point, RISTRETTO_BASEPOINT_COMPRESSED);
  ristretto_encode(bytes, &point);

  for (i=0; i<32; i++) {
    if (bytes[i] != RISTRETTO_BASEPOINT_COMPRESSED[i]) {
      PRINT("byte %d did not match: original=%u encoded=%u",
            i, RISTRETTO_BASEPOINT_COMPRESSED[i], bytes[i]);
      result = 0;
    }
  }

  if (result != 1) {
    printf("FAIL\n");
  } else {
    printf("OKAY\n");
  }

  return (int)result;
}

int test_uint8_32_ct_eq()
{
  uint8_t zero[32] = { 0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0,
                       0, 0, 0, 0, 0, 0, 0, 0, };
  uint8_t one[32] = { 1, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, };
  int ret = 1;

  printf("test 32 byte array equality (0==0): ");
  if (uint8_32_ct_eq(zero, zero) != 1) {
    printf("FAIL\n");
    ret = 0;
  } else {
    printf("OKAY\n");
  }

  printf("test 32 byte array equality (0==1): ");
  if (uint8_32_ct_eq(zero, one) != 0) {
    printf("FAIL\n");
    ret = 0;
  } else {
    printf("OKAY\n");
  }

  return ret;
}

int test_ristretto_ct_eq()
{
  ristretto_point_t a, b;
  int result;

  printf("test ristretto constant time equality check: ");

  ristretto_decode(&a, RISTRETTO_BASEPOINT_COMPRESSED);
  ristretto_decode(&b, RISTRETTO_BASEPOINT_COMPRESSED);

  result = ristretto_ct_eq(&a, &b);

  if (result != 1) {
    printf("FAIL\n");
  } else {
    printf("OKAY\n");
  }

  return result;
}

int main(int argc, char **argv)
{
  int result;

  result  = test_invsqrt_random_field_element();
  result &= test_uint8_32_ct_eq();
  result &= test_ristretto_decode_random_invalid_point();
  result &= test_ristretto_decode_basepoint();
  result &= test_curve25519_expand_random_field_element();
  result &= test_curve25519_expand_basepoint();
  result &= test_curve25519_expand_identity();
  result &= test_ge25519_unpack_pack();
  result &= test_ristretto_encode_identity();
  result &= test_ristretto_encode_basepoint();
  result &= test_ristretto_encode_small_multiples_of_basepoint();
  result &= test_ristretto_ct_eq();

  return result;
}
