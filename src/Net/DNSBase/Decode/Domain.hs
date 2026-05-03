{-|
Module      : Net.DNSBase.Decode.Domain
Description : Wire-form domain decoders (compression-aware and compression-free)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

Two 'Net.DNSBase.Decode.State.SGet' actions for reading a
'Net.DNSBase.Domain.Domain' from wire form: 'getDomain' follows
DNS name-compression pointers ([RFC 1035 section
4.1.4](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4))
for RR types that allow compressed names on input; 'getDomainNC'
rejects compression pointers, for RR types that forbid them (such
as RRSIG's signer name and the SVCB target).
-}

module Net.DNSBase.Decode.Domain
    ( -- * Read domain names from wire messages
      getDomain
    , getDomainNC
    ) where

import Net.DNSBase.Decode.Internal.Domain
