# Base DNS library with extensible core types

A DNS stub-resolver library with a typed `RData` model and a runtime
extension API.  The IO layer is derived from Kazu Yamamoto's
[`dns`](https://hackage.haskell.org/package/dns) package; what
`dnsbase` layers on top sits in the RR-data model and the
configuration story.

Every RR type's payload is modeled via a dedicated Haskell type —
these include, for example, the recent SVCB / HTTPS service-binding
records, with up-to-date extensible SvcParam coverage.  EDNS option
support includes Extended DNS Errors (EDE) with a user-extensible
info-code name table.  Coverage of both widely used and historical
DNS RR types is comprehensive — only the most marginal obsolete or
experimental types remain unimplemented.

Applications can extend the library with any *missing* RRtypes,
EDNS(0) options, or SVCB / HTTPS SvcParam values.
Application-specified data types take precedence over any existing
or later-added built-in implementations.

Extensions are registered by constructing a pure resolver
configuration value, rather than via IO actions on mutable global
state.  Adding custom data types to the library does not require a
source-code fork.  See
[Adding a custom RR type](https://hackage.haskell.org/package/dnsbase/docs/Net-DNSBase-Extensible.html#customRRtype)
and
[Adding a custom EDNS option](https://hackage.haskell.org/package/dnsbase/docs/Net-DNSBase-Extensible.html#customEDNS)
for detailed examples.

The basic lookup interface (`lookupA`, `lookupMX`, `lookupTXT`, …)
is deliberately similar to `dns`; the differences are concentrated
in the typed-data layer and the configuration surface.

## Basic MX lookup example

The example below prints the MX records of `ietf.org`, if any, or an error
message if the answer can't be obtained.

The compile-time literal splice used here is `dnLit8`, the octet-level form
that accepts any RFC 1035 master-file string (the input is treated as raw
bytes, with `\DDD` and `\C` escapes).  For IDN-aware literals — strict
IDNA2008 validation, U-label encoding to A-labels, optional cross-label Bidi
checks — use `dnLit` from `Net.DNSBase.Domain` with a parser from the
companion `idna2008` package; see the `dnLit` haddock for the composition
idiom.

```haskell
{-# LANGUAGE
    BlockArguments
  , LambdaCase
  , RecordWildCards
  , TemplateHaskell
  #-}
import Control.Exception (throwIO)
import Net.DNSBase
import System.IO (stdout)

main :: IO ()
main = makeResolvSeed defaultResolvConf >>= \ case
    Right seed -> withResolver seed \ r ->
        lookupMX r $$(dnLit8 "ietf.org") >>= \ case
            Right mxs -> hPutBuilder stdout $ foldr presentLn mempty mxs
            Left errs -> throwIO errs
    Left errs -> throwIO errs
```

## Custom extensions

The [`demos/`](https://github.com/dnsbase/dnsbase/tree/main/demos)
directory contains worked examples for each of the three extension
targets:

- [`demoextrr.hs`](https://github.com/dnsbase/dnsbase/blob/main/demos/demoextrr.hs)
  — adding a custom RR type, by shadowing the standard `A` record
  with a raw-`Word32` representation that presents each address as
  eight hex nibbles under a made-up name `HEXA`.  Shows the
  `KnownRData` instance shape and registration via
  `registerRRtype`.
- [`demoextopt.hs`](https://github.com/dnsbase/dnsbase/blob/main/demos/demoextopt.hs)
  — adding an EDNS(0) option (the EDNS cookie, RFC 7873), queried
  directly against `ns1.isc.org` to elicit a server cookie.  Shows
  the `KnownEdnsOption` instance shape, registration via
  `registerEdnsOption`, and per-call option injection via
  `optCtlAdd`.
- [`demoextspv.hs`](https://github.com/dnsbase/dnsbase/blob/main/demos/demoextspv.hs)
  — adding (here, shadowing) an HTTPS / SVCB service parameter, by
  re-implementing the `ipv4hint` key (codepoint 4) with a
  raw-`Word32`-list representation and a hex presentation form
  under a made-up name `IPV4HEX`.  Shows the `KnownSVCParamValue`
  instance shape and the registration via `extendRRwithType`
  applied to both `T_svcb` and `T_https` (SVCB-shaped RRs share
  the SvcParam codec map).

Each demo is a self-contained program; copy one into a project
and adjust the queries to taste.
