{-|
Module      : Net.DNSBase.Encode.State
Description : Wire-form encoder monad and primitive byte/sequence encoders
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 'SPut' encoder monad for serialising DNS wire-form data,
plus primitive writers ('put8', 'put16', ...), DNS-style
helpers ('putDomain', 'putWireForm'), length-prefixed
byte-string writers, and the high-level driver functions
'encodeCompressed' / 'encodeVerbatim'.  Used by authors of
'Net.DNSBase.RData.KnownRData' and 'Net.DNSBase.EDNS.Option.KnownEdnsOption' instances to implement value-side
encoding; most applications will not use this module directly.

'putDomain' applies DNS name compression
([RFC 1035 section 4.1.4](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4))
when the surrounding driver permits it; 'putWireForm' is the
compression-free counterpart for RR types whose target domains
forbid compression on encode.
-}

module Net.DNSBase.Encode.State
    ( -- * Low level DNS data encoding primitives
      EncodeErr(..)
    , ErrorContext
    , SPut, SPutM, localSPut
    , buildCompressed
    , encodeCompressed
    , buildVerbatim
    , encodeVerbatim
    , putDomain
    , putWireForm
    , put8
    , put16
    , put32
    , put64
    , putIPv4
    , putIPv6
    , putByteString
    , putByteStringLen8
    , putByteStringLen16
    , putShortByteString
    , putShortByteStringLen8
    , putShortByteStringLen16
    , putUtf8Text
    , putUtf8TextLen8
    , putUtf8TextLen16
    , putSizedBuilder
    , putReplicate
    -- * Encoder state mutation
    , passLen
    , failWith
    , setContext
    ) where

import Net.DNSBase.Encode.Internal.State
