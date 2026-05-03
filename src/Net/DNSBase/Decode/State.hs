{-|
Module      : Net.DNSBase.Decode.State
Description : Wire-form decoder monad and primitive byte/sequence decoders
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 'SGet' decoder monad for parsing DNS wire-form data, plus the
primitive readers ('get8', 'get16', 'get32', ...), DNS-style
helpers ('getDnsTime', 'getIPv4', 'getIPv6'), length-prefixed
byte-string readers, and the sequence and sandboxing combinators
('getVarWidthSequence', 'fitSGet', 'seekSGet').  Used by authors
of 'Net.DNSBase.RData.KnownRData' and
'Net.DNSBase.EDNS.Option.KnownEdnsOption' instances to implement the
value-side decoding; most applications will not use this module
directly.
-}

module Net.DNSBase.Decode.State
    (
    -- * DNS message element parser
      SGet
    -- * Internal state accessors
    , getPosition
    , getChrono
    -- * Generic low-level decoders
    , get8
    , get16
    , get32
    , get64
    , getInt8
    , getInt16
    -- * DNS-specific low-level decoders
    , getIPv4
    , getIPv4Net
    , getIPv6
    , getIPv6Net
    , getDnsTime
    -- * Octet-string decoders
    , skipNBytes
    , getNBytes
    , getShortByteString
    , getShortNByteString
    , getShortByteStringLen8
    , getShortByteStringLen16
    , getUtf8Text
    , getUtf8TextLen8
    , getUtf8TextLen16
    -- * Sequence decoders
    , getVarWidthSequence
    , getFixedWidthSequence
    -- * Decoder sandboxing
    , seekSGet
    , fitSGet
    -- * Decoder failure
    , failSGet
    -- * Decoder driver
    , decodeAtWith
    ) where

import Net.DNSBase.Decode.Internal.State
