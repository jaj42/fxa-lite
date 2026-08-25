# The crypto core

`fxa_lite.crypto` is where the onepw protocol lives, and it is the part of this
codebase most likely to be read by someone porting it somewhere else. The
docstrings carry the protocol constants and — more usefully — the traps in them:
the lowercase `k` in `unwrapBkey`, the HKDF whose input keying material is a hex
string's ASCII bytes rather than the bytes it spells, the `aud` that is not the
client id.

Everything below is checked against known-answer vectors transcribed from the
reference's own `*.spec.ts` files, in `tests/vectors/`. The browser half of the
same protocol — `content/assets/crypto.js` — is run under `node` against those
same vectors, which is the only way to know the two agree.

```{eval-rst}
.. currentmodule:: fxa_lite.crypto
```

## HKDF

```{eval-rst}
.. automodule:: fxa_lite.crypto.hkdf
```

## The onepw protocol

```{eval-rst}
.. automodule:: fxa_lite.crypto.onepw
```

## Token derivation

```{eval-rst}
.. automodule:: fxa_lite.crypto.tokens
```

## Scoped keys

```{eval-rst}
.. automodule:: fxa_lite.crypto.scoped_keys
```

## JOSE: RS256 and compact ECDH-ES

```{eval-rst}
.. automodule:: fxa_lite.crypto.jose
```
