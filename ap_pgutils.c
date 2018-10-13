#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <inttypes.h>

#include "postgres.h"
#include "catalog/pg_type.h"
#include "fmgr.h"
#include "utils/builtins.h"

#include "openssl/hmac.h"

#include "ap_pgutils.h"
#include "argon2.h"
#include "argon2/src/core.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

PG_FUNCTION_INFO_V1(pg_gethostname);
extern Datum pg_gethostname(PG_FUNCTION_ARGS)
{
  char host_buf[256];
  text *result;
  int status;
  status = gethostname(host_buf, 256);
  if (status == 0) {
    int hlen = strlen(host_buf);
    result = palloc(VARHDRSZ + hlen + 1);
    strcpy(VARDATA(result), host_buf);
    SET_VARSIZE(result, VARHDRSZ + hlen + 1);
    return (Datum) result;
  } else {
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("gethostname() failed")));
    return (Datum) NULL;
  }
}

PG_FUNCTION_INFO_V1(pg_argon2);
extern Datum pg_argon2(PG_FUNCTION_ARGS)
{
  text *password = PG_GETARG_TEXT_P(0);
  int pwdlen = VARSIZE(password) - VARHDRSZ;
  text *salt = PG_GETARG_TEXT_P(1);
  int saltlen = VARSIZE(salt) - VARHDRSZ;
  int t_cost = PG_GETARG_INT32(2);
  int log2_mem = PG_GETARG_INT32(3);
  int outlen = PG_GETARG_INT32(4);
  text *variant_text = PG_GETARG_TEXT_P(5);
  char variant = *VARDATA(variant_text);
  int parallelism = PG_GETARG_INT32(6);
  text *result;
  int encodedlen, m_cost, status;

  /* check cost parameters */
  if (t_cost <= 0) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("iterations must be a positive integer, not %d", t_cost)));
    return (Datum) NULL;
  }
  if (log2_mem <= 0 || log2_mem > 32) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("log2_mem must be between 1 and 32, not %d", log2_mem)));
    return (Datum) NULL;
  }
  m_cost = 1 << log2_mem;
  if (outlen <= 0) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("hash length must be a positive integer, not %d",
                    outlen)));
    return (Datum) NULL;
  }
  if (variant != 'd' && variant != 'i') {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("hash variant must be 'i' or 'd', got '%c'", variant)));
    return (Datum) NULL;
  }
  if (parallelism <= 0) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("parallelism must be a positive integer, not %d",
                    parallelism)));
    return (Datum) NULL;
  }

  encodedlen = argon2_encodedlen(t_cost, m_cost, 1, saltlen, outlen);
  result = palloc(VARHDRSZ + encodedlen);
  SET_VARSIZE(result, VARHDRSZ + encodedlen);
  status = argon2_hash(t_cost, m_cost, parallelism,
                       VARDATA(password), pwdlen,
                       VARDATA(salt), saltlen, NULL, outlen,
                       VARDATA(result), encodedlen,
                       variant == 'i' ? Argon2_i : Argon2_d,
                       ARGON2_VERSION_NUMBER);
  if (status != 0) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INTERNAL_ERROR),
             errmsg("argon2 hash failed, err=%s",
                    argon2_error_message(status))));
    return (Datum) NULL;
  }
  return (Datum) result;
}

PG_FUNCTION_INFO_V1(pg_argon2_verify);
extern Datum pg_argon2_verify(PG_FUNCTION_ARGS)
{
  char *encoded = text_to_cstring(PG_GETARG_TEXT_P(0));
  text *password = PG_GETARG_TEXT_P(1);
  int pwdlen = VARSIZE(password) - VARHDRSZ;
  int status;
  char variant;

  /* check parameters */
  if (strncmp(encoded, "$argon2", 7) != 0 || strlen(encoded) < 8) {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("Not a valid Argon2 hash: \"%s\"", encoded)));
    return (Datum) NULL;
  }
  variant = encoded[7];
  if (variant != 'i' && variant != 'd') {
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
             errmsg("Argon2 variant must be 'i' or 'd', not '%c'", variant)));
    return (Datum) NULL;
  }

  status= argon2_verify(encoded, VARDATA(password), pwdlen,
                        variant == 'i' ? Argon2_i : Argon2_d);
  switch (status) {
  case 0:
    PG_RETURN_BOOL(1);
  case ARGON2_VERIFY_MISMATCH:
    PG_RETURN_BOOL(0);
  default:
    secure_wipe_memory(VARDATA(password), pwdlen);
    ereport(ERROR,
            (errcode(ERRCODE_INTERNAL_ERROR),
             errmsg("argon2 verification failed, err=%s",
                    argon2_error_message(status))));
    return (Datum) NULL;
  }
}


PG_FUNCTION_INFO_V1(pg_b32_encode);
static unsigned char b32_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

extern Datum pg_b32_encode(PG_FUNCTION_ARGS)
{
  bytea *raw = PG_GETARG_BYTEA_P(0);
  int rawlen = VARSIZE(raw) - VARHDRSZ;
  text *out;
  int i, j, outlen, bits;
  unsigned int accum;
  unsigned char *rawdata = (unsigned char *) VARDATA(raw);

  outlen = (8 * rawlen) / 5 + (((8 * rawlen) % 5) ? 1 : 0);
  out = palloc(VARHDRSZ + outlen);
  SET_VARSIZE(out, VARHDRSZ + outlen);

  /* encode in chunks of up to 8 bytes */
  accum = 0;
  j = 0;
  for (i=0; i<rawlen; i++) {
    accum = (accum << 8) | rawdata[i];
    bits += 8;
    while (bits >= 5) {
      unsigned int b = accum & (0x1f << (bits - 5));
      accum ^= b;
      b >>= bits - 5;
      VARDATA(out)[j++] = b32_table[b];
      bits -= 5;
    }
  }
  if (bits) {
    accum <<= 5 - bits;
    VARDATA(out)[j++] = b32_table[accum & 0x20];
  }

  return (Datum) out;
}
