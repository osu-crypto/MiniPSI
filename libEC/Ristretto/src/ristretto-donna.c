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

static uint8_t uchar_ct_eq(const uint8_t a, const uint8_t b);
static uint8_t bignum25519_is_negative(unsigned char bytes[32]);

/**
 * Check if two bytes are equal in constant time.
 *
 * Returns 1 iff the bytes are equals and 0 otherwise.
 */
static uint8_t uchar_ct_eq(const unsigned char a, const unsigned char b)
{
  unsigned char x = ~(a ^ b);

  x &= x >> 4;
  x &= x >> 2;
  x &= x >> 1;

  return (uint8_t)x;
}

/**
 * Compress a group element into a 32-byte buffer.
 *
 * This function is exactly the same as `ge25519_pack()`, except that
 * it does not optionally XOR in a parity bit at the end if the
 * x-coordinate was negative.
 **/
void ge25519_pack_without_parity(unsigned char bytes[32], const ge25519 *p) {
	bignum25519 tx, ty, zi;

	curve25519_recip(zi, p->z);
	curve25519_mul(tx, p->x, zi);
	curve25519_mul(ty, p->y, zi);
	curve25519_contract(bytes, ty);
}

/**
 * Check if two 32 bytes arrays are equal in constant time.
 *
 * Returns 1 iff the bytes are equals and 0 otherwise.
 */
uint8_t uint8_32_ct_eq(const unsigned char a[32], const unsigned char b[32])
{
  unsigned char x = 1;
  unsigned char i;

  for (i=0; i<32; i++) {
    x &= uchar_ct_eq(a[i], b[i]);
  }

  return (uint8_t)x;
}

/**
 * Check if two field elements are equal in constant time.
 *
 * Returns 1 iff the elements are equals and 0 otherwise.
 */
uint8_t bignum25519_ct_eq(const bignum25519 a, const bignum25519 b)
{
  unsigned char c[32];
  unsigned char d[32];

  curve25519_contract(c, a);
  curve25519_contract(d, b);

  return uint8_32_ct_eq(c, d);
}

/**
 * Ascertain if a field element (encoded as bytes) is negative.
 *
 * Returns 1 iff the element is negative and 0 otherwise.
 */
static uint8_t bignum25519_is_negative(unsigned char bytes[32])
{
  uint8_t low_bit_is_set = bytes[0] & 1;

  PRINT("low_bit_is_set = %d", low_bit_is_set);

  return low_bit_is_set;
}

uint8_t curve25519_sqrt_ratio_i(bignum25519 out, const bignum25519 u, const bignum25519 v)
{
  bignum25519 tmp, v3, v7, r, r_prime, r_negative, check, i, u_neg, u_neg_i;
  unsigned char r_bytes[32];
  uint8_t r_is_negative;
  uint8_t correct_sign_sqrt;
  uint8_t flipped_sign_sqrt;
  uint8_t flipped_sign_sqrt_i;
  uint8_t was_nonzero_square;
  uint8_t should_rotate;

  PRINT("sqrt_ratio_i with u,v = "); fe_print(u); fe_print(v);

  curve25519_square(tmp, v);      // v²
  curve25519_mul(v3, tmp, v);     // v³
  curve25519_square(tmp, v3);      // v⁶
  curve25519_mul(v7, tmp, v);     // v⁷
  curve25519_mul(tmp, u, v7);     // u*v^7
  curve25519_pow_two252m3(r, tmp); // (u*v^7)^{(p-5)/8}
  curve25519_mul(r, r, u);        // (u)*(u*v^7)^{(p-5)/8}
  curve25519_mul(r, r, v3);        // (u)*(u*v^7)^{(p-5)/8}
  curve25519_square(tmp, r);       // tmp = r^2
  curve25519_mul(check, v, tmp);  // check = r^2 * v

  PRINT("r = "); fe_print(r);
  PRINT("check = "); fe_print(check);
  
  curve25519_neg(u_neg, u);
  curve25519_mul(u_neg_i, u_neg, SQRT_M1);

  correct_sign_sqrt = bignum25519_ct_eq(check, u);
  flipped_sign_sqrt = bignum25519_ct_eq(check, u_neg);
  flipped_sign_sqrt_i = bignum25519_ct_eq(check, u_neg_i);

  PRINT("correct_sign_sqrt = %d", correct_sign_sqrt);
  PRINT("flipped_sign_sqrt = %d", flipped_sign_sqrt);
  PRINT("flipped_sign_sqrt_i = %d", flipped_sign_sqrt_i);

  curve25519_mul(r_prime, r, SQRT_M1);
  should_rotate = flipped_sign_sqrt | flipped_sign_sqrt_i;
  curve25519_swap_conditional(r, r_prime, should_rotate);

  // Choose the non-negative square root
  curve25519_contract(r_bytes, r);
  r_is_negative = bignum25519_is_negative(r_bytes);
  curve25519_neg(r_negative, r);
  curve25519_swap_conditional(r, r_negative, r_is_negative);
  PRINT("r = "); fe_print(r);

  was_nonzero_square = correct_sign_sqrt | flipped_sign_sqrt;
  PRINT("was_nonzero_square = %d", was_nonzero_square);

  curve25519_copy(out, r);

  return was_nonzero_square;
}

/**
 * Calculate either `sqrt(1/v)` for a field element `v`.
 *
 * Returns:
 *  - 1 and stores `+sqrt(1/v)` in `out` if `v` was a non-zero square,
 *  - 0 and stores `0` in `out` if `v` was zero,
 *  - 0 and stores `+sqrt(i/v)` in `out` if `v` was a non-zero non-square.
 */
uint8_t curve25519_invsqrt(bignum25519 out, const bignum25519 v)
{
  return curve25519_sqrt_ratio_i(out, one, v);
}

/**
 * Attempt to decompress `bytes` to a Ristretto group `element`.
 *
 * Returns 0 if the point could not be decoded and 1 otherwise.
 */
int ristretto_decode(ristretto_point_t *element, const unsigned char bytes[32])
{
  bignum25519 s, ss;
  bignum25519 u1, u1_sqr, u2, u2_sqr;
  bignum25519 v, i, minus_d, dx, dy, x, y, t;
  bignum25519 tmp;
  unsigned char s_bytes_check[32];
  unsigned char x_bytes[32];
  unsigned char t_bytes[32];
  uint8_t s_encoding_is_canonical;
  uint8_t s_is_negative;
  uint8_t x_is_negative;
  uint8_t t_is_negative;
  uint8_t y_is_zero;
  uint8_t ok;

  // Step 1: Check that the encoding of the field element is canonical
  curve25519_expand(s, bytes);
  curve25519_contract(s_bytes_check, s);

  s_encoding_is_canonical = uint8_32_ct_eq(bytes, s_bytes_check);
  s_is_negative = bignum25519_is_negative(s_bytes_check);

  // Bail out if the field element encoding was non-canonical or negative
  if (s_encoding_is_canonical == 0 || s_is_negative == 1) {
      return 0;
  }

  // Step 2: Compute (X:Y:Z:T)
  // XXX can we eliminate these reductions
  curve25519_square(ss, s);
  curve25519_sub_reduce(u1, one, ss);    //  1 + as², where a = -1, d = -121665/121666
  curve25519_add_reduce(u2, one, ss);    //  1 - as²
  curve25519_square(u1_sqr, u1);         // (1 + as²)²
  curve25519_square(u2_sqr, u2);         // (1 - as²)²
  curve25519_neg(minus_d, EDWARDS_D);    // -d               // XXX store as const?
  curve25519_mul(tmp, minus_d, u1_sqr);  // ad(1+as²)²
  curve25519_sub_reduce(v, tmp, u2_sqr); // ad(1+as²)² - (1-as²)²
  curve25519_mul(tmp, v, u2_sqr);        // v = (ad(1+as²)² - (1-as²)²)(1-as²)²

  ok = curve25519_invsqrt(i, tmp);       // i = 1/sqrt{(ad(1+as²)² - (1-as²)²)(1-as²)²}

  // Step 3: Calculate x and y denominators, then compute x.
  curve25519_mul(dx, i, u2);             // 1/sqrt(v)
  curve25519_mul(tmp, dx, v);            // v/sqrt(v)
  curve25519_mul(dy, i, tmp);            // 1/(1-as²)
  curve25519_add_reduce(tmp, s, s);      // 2s
  curve25519_mul(x, tmp, dx);            // x = |2s/sqrt(v)| = +sqrt(4s²/(ad(1+as²)² - (1-as²)²))
  curve25519_contract(x_bytes, x);
  
  // Step 4: Conditionally negate x if it's negative.
  x_is_negative = bignum25519_is_negative(x_bytes);

  curve25519_neg(tmp, x);
  curve25519_swap_conditional(x, tmp, x_is_negative);

  // Step 5: Compute y = (1-as²)/(1+as²) and t = {(1+as²)sqrt(4s²/(ad(1+as²)²-(1-as²)²))}/(1-as²)
  curve25519_mul(y, u1, dy);
  curve25519_mul(t, x, y);
  curve25519_contract(t_bytes, t);
  
  t_is_negative = bignum25519_is_negative(t_bytes);

  if (ok == 0 || t_is_negative == 1 || y_is_zero == 1) {
    return 0;
  }

  curve25519_copy(element->point.x, x);
  curve25519_copy(element->point.y, y);
  curve25519_copy(element->point.z, one);
  curve25519_copy(element->point.t, t);

  return 1;
}

void ristretto_encode(unsigned char bytes[32], const ristretto_point_t *element)
{
  bignum25519 u1, u2, i1, i2, z_inv, den_inv, ix, iy, invsqrt, tmp1, tmp2;
  bignum25519 x, y, y_neg, s, s_neg;
  bignum25519 enchanted_denominator;
  unsigned char contracted[32];
  uint8_t x_zinv_is_negative;
  uint8_t s_is_negative;
  uint8_t rotate;

  curve25519_add_reduce(tmp1, element->point.z, element->point.y);
  curve25519_sub_reduce(tmp2, element->point.z, element->point.y);
  curve25519_mul(u1, tmp1, tmp2);
  curve25519_mul(u2, element->point.x, element->point.y);

  curve25519_mul(tmp1, u1, u2);

  // This is always square so we don't need to check the return value
  curve25519_invsqrt(invsqrt, tmp1);

  curve25519_mul(i1, invsqrt, u1);
  curve25519_mul(i2, invsqrt, u2);
  curve25519_mul(tmp1, i2, element->point.t);
  curve25519_mul(z_inv, tmp1, i1);
  curve25519_mul(ix, element->point.x, SQRT_M1);
  curve25519_mul(iy, element->point.y, SQRT_M1);
  curve25519_mul(enchanted_denominator, i1, INVSQRT_A_MINUS_D);
  curve25519_mul(tmp1, element->point.t, z_inv);
  curve25519_contract(contracted, tmp1);

  rotate = bignum25519_is_negative(contracted);

  curve25519_copy(x, element->point.x);
  curve25519_copy(y, element->point.y);

  // Rotate into the distinguished Jacobi quartic quadrant
  curve25519_swap_conditional(x, iy, rotate);
  curve25519_swap_conditional(y, ix, rotate);
  curve25519_swap_conditional(i2, enchanted_denominator, rotate);

  // Next we torque the points to be non-negative

  // Conditionally flip the sign of y to be positive
  curve25519_mul(tmp1, element->point.x, z_inv);
  curve25519_contract(contracted, tmp1);

  x_zinv_is_negative = bignum25519_is_negative(contracted);

  curve25519_neg(y_neg, y);
  curve25519_swap_conditional(y, y_neg, x_zinv_is_negative);

  curve25519_sub_reduce(tmp1, element->point.z, element->point.y);
  curve25519_mul(s, i2, tmp1);
  curve25519_contract(contracted, s);

  // Conditionally flip the sign of s to be positive
  s_is_negative = bignum25519_is_negative(contracted);

  curve25519_neg(s_neg, s);
  curve25519_swap_conditional(s, s_neg, s_is_negative);

  // Output the compressed form of s
  curve25519_contract(bytes, s);
}

/**
 * Produce a Ristretto group element from a 512-bit hash digest.
 *
 * Returns 1 on success, otherwise returns 0.
 */
int ristretto_from_uniform_bytes(ristretto_point_t *element, const unsigned char bytes[64])
{
  return 1;
}

/**
 * Test equality of two `ristretto_point_t`s in constant time.
 *
 * Returns 1 if the two points are equal, and 0 otherwise.
 */
int ristretto_ct_eq(const ristretto_point_t *a, const ristretto_point_t *b)
{
  bignum25519 x1y2, y1x2, x1x2, y1y2;
  uint8_t check_one, check_two;

  curve25519_mul(x1y2, a->point.x, b->point.y);
  curve25519_mul(y1x2, a->point.y, b->point.x);
  curve25519_mul(x1x2, a->point.x, b->point.x);
  curve25519_mul(y1y2, a->point.y, b->point.y);

  check_one = bignum25519_ct_eq(x1y2, y1x2);
  check_two = bignum25519_ct_eq(x1x2, y1y2);

  return check_one | check_two;
}
