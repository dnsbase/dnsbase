module Net.DNSBase.RData
    ( RData(..)
    , KnownRData(..)
    , rdataType
    , monoRData
    , OpaqueRData(..)
    , opaqueRData
    , toOpaque
    , fromOpaque
    , module Net.DNSBase.Decode.State
    , module Net.DNSBase.Encode.Metric
    , module Net.DNSBase.Encode.State
    ) where

import Net.DNSBase.Decode.Internal.RData
import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Internal.RData
