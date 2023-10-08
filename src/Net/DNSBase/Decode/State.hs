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
