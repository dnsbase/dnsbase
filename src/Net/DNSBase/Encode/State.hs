module Net.DNSBase.Encode.State
    ( -- * Low level DNS data encoding primitives
      EncodeErr(..)
    , SPut
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
    , putInt8
    , putInt16
    , putInt32
    , putIPv4
    , putIPv6
    , putByteString
    , putByteStringLen8
    , putByteStringLen16
    , putShortByteString
    , putShortByteStringLen8
    , putShortByteStringLen16
    , putUtf8TextLen8
    , putUtf8TextLen16
    , putSizedBuilder
    , putReplicate
    -- 'safe' re-exports of RWST functions
    , passLen
    , failWith
    , setContext
    ) where

import Net.DNSBase.Encode.Internal.State
