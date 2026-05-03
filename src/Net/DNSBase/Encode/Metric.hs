{-|
Module      : Net.DNSBase.Encode.Metric
Description : Length-tracking Builder for wire-form encoding
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

'SizedBuilder' is a 'Data.ByteString.Builder' paired with its
byte length, accumulated as the builder is assembled.  Used
inside RR-data encoders when an outer length-prefixed field
needs the encoded value's length up front (RDLENGTH and the
16-bit length prefixes that introduce SVCB option values, EDNS
option values, and similar).  The @mb*@ converters wrap the
corresponding low-level builders so their byte-cost is
tracked.
-}

module Net.DNSBase.Encode.Metric
    ( SizedBuilder
    -- exported pattern
    , pattern SizedBuilder
    -- exported converters
    , mbErr
    , mbWord8
    , mbWord16
    , mbWord32
    , mbWord64
    , mbByteString
    , mbByteStringLen8
    , mbByteStringLen16
    , mbShortByteString
    , mbShortByteStringLen8
    , mbShortByteStringLen16
    , mbIPv4
    , mbIPv6
    ) where

import Net.DNSBase.Encode.Internal.Metric
