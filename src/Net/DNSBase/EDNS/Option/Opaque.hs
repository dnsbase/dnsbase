{-|
Module      : Net.DNSBase.EDNS.Option.Opaque
Description : Fallback wrapper for unrecognised EDNS options
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

'OpaqueOption' is the carrier the decoder falls back to when it
sees an EDNS option code that no
'Net.DNSBase.EDNS.Option.KnownEdnsOption' instance in the resolver's
option map handles.  The option's contents are left as raw bytes
and presented in the generic [RFC
3597](https://datatracker.ietf.org/doc/html/rfc3597) form, so
applications can still inspect and round-trip the value.  The
option code is carried as a type-level natural, so
'OpaqueOption' values with different codes have distinct types.
-}

module Net.DNSBase.EDNS.Option.Opaque
    ( OpaqueOption(..)
    , opaqueEdnsOption
    )
    where

import Net.DNSBase.EDNS.Internal.Option.Opaque
