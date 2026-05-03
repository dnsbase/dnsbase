# Changelog

## 0.5.0.0

- The `IsString` instances of `Domain` and `Mbox` have been withdrawn.
- Refactored `dnLit` and `mbLit` to support pluggable external parsers
  compatible with the `idna2008` package.  The original octe-string
  parser implementations are renamed `parseDomain8`, `parseMbox8`,
  `dnLit8` and `mbLit8`.

## 0.3

Require GHC 9.10.

## 0.2

Require GHC 9.8.

## 0.1

Initial fork from Kazu Yamamoto's
[`dns`](https://hackage.haskell.org/package/dns); has evolved
independently since.
