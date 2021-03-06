CREATE OR REPLACE FUNCTION
gethostname() RETURNS TEXT
LANGUAGE C STABLE
AS '$libdir/ap_pgutils.so', 'pg_gethostname';

CREATE OR REPLACE FUNCTION
argon2(
  IN password TEXT,
  IN salt TEXT,
  IN iterations INT DEFAULT 3,
  IN log2_mem INT DEFAULT 12,
  IN outlen INT DEFAULT 32,
  IN variant TEXT DEFAULT 'i',
  IN parallelism INT DEFAULT 1
) RETURNS TEXT
LANGUAGE C STABLE
AS '$libdir/ap_pgutils.so', 'pg_argon2';

CREATE OR REPLACE FUNCTION
argon2_verify(
  IN encoded TEXT,
  IN password TEXT
) RETURNS BOOL
LANGUAGE C STABLE
AS '$libdir/ap_pgutils.so', 'pg_argon2_verify';

CREATE OR REPLACE FUNCTION
b32_encode(
  IN data BYTEA
) RETURNS TEXT
LANGUAGE C STABLE
AS '$libdir/ap_pgutils.so', 'pg_b32_encode';
