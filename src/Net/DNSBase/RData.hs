{-|
Module      : Net.DNSBase.RData
Description : Existential wrapper and extensibility hooks for RR-data payloads
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The existential 'RData' wrapper holds any 'KnownRData'
instance, so a heterogeneous list of records — an answer
section, a zone — can share a single Haskell type.
'fromRData' and 'rdataType' recover the underlying value or
its type code; 'monoRData' is the bulk form, filtering a list
of 'RData' values by type.

Unrecognised RR types decode into 'OpaqueRData', which
preserves the raw wire bytes under a type-level codepoint and
presents in the generic
[RFC 3597](https://datatracker.ietf.org/doc/html/rfc3597)
@\#@-prefixed form.

Advanced applications can add support for any missing RR types,
not yet supported by the library, by implementing a corresponding
'KnownRData' instance and exposing it to the resolver via
'Net.DNSBase.Resolver.registerRRtype' (see
"Net.DNSBase.Resolver").  'KnownRData' carries any per-type
extension value ('RDataExtensionVal') the codec consumes.
RR types that admit type-driven extension (presently, just SVCB
and HTTPS) /also/ implement a 'TypeExtensible' instance whose
'extendByType' method is invoked by
'Net.DNSBase.Resolver.extendRRwithType'.

The encoder and decoder combinator modules are re-exported for
the benefit of authors of new 'KnownRData' instances; ordinary
callers do not need them.
-}

module Net.DNSBase.RData
    ( -- * Basic RData API
      RData(..)
    , fromRData
    , monoRData
    , rdataType
      -- * Opaque RData
    , OpaqueRData(..)
    , opaqueRData
    , toOpaqueRData
    , fromOpaqueRData
      -- * Extensibility
    , KnownRData(..)
    , TypeExtensible(..)
    , RDataCodec
      -- * Encoder and Decoder combinators
    , module Net.DNSBase.Decode.State
    , module Net.DNSBase.Encode.Metric
    , module Net.DNSBase.Encode.State
    ) where

import Net.DNSBase.Decode.Internal.RData
import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Extensible
import Net.DNSBase.Internal.RData
