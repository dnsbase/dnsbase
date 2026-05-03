{-|
Module      : Net.DNSBase.Error
Description : Resolver, protocol, and encoder error types
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

'DNSError' is the sum type returned by all failed lookups in
"Net.DNSBase.Lookup".  Its constructors split by source: network
problems ('NetworkError'), protocol-level decode or response-code
failures ('ProtocolError'), API misuse errors ('UserError'), and
so on.  Information about the context in which the error occured
is included when available.  'EncodeErr' is the analogous sum
returned by failures of the wire-form encoder.
-}

module Net.DNSBase.Error
    ( DNSError(..)
    , DnsXprt(..)
    , EncodeErr(..)
    , NetworkContext(..)
    , ProtocolContext(..)
    , UserContext(..)
    , DecodeContext(..)
    , EncodeContext(..)
    , DnsSection(..)
    , MessageSource(..)
    ) where

import Net.DNSBase.Internal.Error
