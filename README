Testing various openssl on NeXT

```
make
```

To make with differences,

```
make SSL_DIR=~/Projects/openssl-1.0.2l.dirty CC=m68k-next-nextstep3-gcc
```

## Test results

### OS 4.2 Intel,

```
$ ./t-rsa-i386.exe
Testing RSA functions with EVP_DigestSign and EVP_DigestVerify
Created signature
Signature: 694B01BFE807B5F2C3FF77D5E2BA722EDDCAA3A98EF42169167A10F5F5BFD4A5F7AA7EDC62C605D832FAFC45CFD699AF883A45FACC86E732B28A48BBBB172218
in(sha256) expect(sha256)
Verified signature

$ ./t-hmac.o
Testing HAMC functions with EVP_DigestSign
HMAC key: C9E7193C9FFBE7C1C2D937A87D9EC5B7CAC774FA574EED3CCE07B3E178CD1F9A
Created signature
Signature: 4B03E2DB870D1C05C5592400672BB5D2F9CDEECA659AB2A07EFA0B37AE6AC13A
Verified signature
```

### m68k

```
$ ./t-rsa.o
Testing RSA functions with EVP_DigestSign and EVP_DigestVerify
Created signature
Signature: 495E192DE09FA389BE81D7F0907532812D6B1EABC948AA94BECA2C7859CCB5B94C2203B4CD85684EC488E190655CC7A4283E7AA5912F749C6056A77FCB0E6C57
EVP_DigestVerifyFinal failed, error 0x4091064
Failed to verify signature, return code 1

 $ ./t-hmac.o
Testing HAMC functions with EVP_DigestSign
HMAC key: 4CC6C661D786BABDE7746038FAF663133DE15CCAAC132C739CA2C11C838047D6
Created signature
Signature: 866B05C7D02367A44C6DE5DB3090383D3E0EC54B01548380467A581B5EA39A43
Verified signature
```
