# ap_pgutils
PostgreSQL extension with utility functions for hostname, argon2 password
hashing and TOTP based 2 factor authentication

## Authentication

### Password hashing

The recommended way to secure passwords in a user database has evolved to keep
up with the rise of inexpensive consumer-class GPUs that are able to run
billions of MD5/SHA1/ calculations per second on programs like
[oclHashcat](http://hashcat.net/oclhashcat/). Here is a
[good introduction](https://hynek.me/articles/storing-passwords/) to the
subject,

The function `argon2` implements the
[Argon2](https://en.wikipedia.org/wiki/Argon2) algorithm, winner of the
[2015 password hashing competition](https://password-hashing.net/).

It takes 2 required arguments:
- `password` (text): the cleartext password you wish to hash
- `salt` (text): the salt to use to protect the password hash from rainbow
  tables
and 5 optional ones:
- `iterations` (int): the number of iterations of the Argon2 algorithm,
  default is 3,
- `log2_mem` (int): the base 2 log of how much memory to use in kilobytes, for
  instance the default `log2mem=12` means use 4MB.
- `outlen` (int): the desired length of the hash, the default is 32
- `variant` (text): wihich variant of Argon2, `'i'` for argon2i (default),
  `'d'` for argon2d
- `parallelism` (int): the Argon2 parallelism factor, default is 1

The result is an Argon2 hash in extended crypt format, as a PostgreSQL TEXT
value.

### Two-factor authentication

The function `totp_verify` implements the [Time-based One-Time Password}
algorithm, as implemented by Google Authenticator,
[Lockdown](http://cocoaapp.com/lockdown/), FreeOTP and a number of others.

It takes 2 required arguments:
- `b32_secret` (text): the Base32-encoded secret shared with the OTP app
- `otp` (int): the 6-digit one-time-password generated by the app
  and one optional argument:
- `tolerance` (int): the tolerance to clock skew in numbers of 30 second
  intervals, e.g. `tolerance=10` would tolerate
  a skew of up to +/- 5 minutes. The default is to not tolerate any skew.

The return value is boolean, True for a successful authentication, False for
authentication failure.

### Miscellaneous

The function `gethostname` returns the system's hostname.

The function `b32_encode` takes a `bytea` and returns it encoded Base32,
without padding.

## License

This work is copyright (c) 2016, Apsalar Inc. and licensed under the same
Creative Commons
[CC0 license](https://creativecommons.org/about/cc0) license as Argon2.

### Argon2

Except for the components listed below, the Argon2 code in this
repository is copyright (c) 2015 Daniel Dinu, Dmitry Khovratovich (main
authors), Jean-Philippe Aumasson and Samuel Neves, and under
[CC0 license](https://creativecommons.org/about/cc0).

The string encoding routines in [`src/encoding.c`](src/encoding.c) are
copyright (c) 2015 Thomas Pornin, and under [CC0
license](https://creativecommons.org/about/cc0).

The BLAKE2 code in [`src/blake2/`](src/blake2) is copyright (c) Samuel
Neves, 2013-2015, and under [CC0
license](https://creativecommons.org/about/cc0).

All licenses are therefore GPL-compatible.