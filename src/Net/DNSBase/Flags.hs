module Net.DNSBase.Flags
    ( -- * DNS Message basic and extneded flags
     DNSFlags(..)
    , basicFlags
    , extendFlags
    , extendedFlags
    , extractOpcode
    , extractRCODE
    , hasAllFlags
    , hasAnyFlags
    , makeDNSFlags
    , maskDNSFlags
    -- * Resolver flag control building blocks
    , FlagOps
    , setFlagBits
    , clearFlagBits
    , resetFlagBits
    , emptyFlagOps
    , applyFlagOps
    ) where

import Net.DNSBase.Internal.Flags
