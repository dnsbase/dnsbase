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
    ) where

import Net.DNSBase.Encode.Internal.Metric
