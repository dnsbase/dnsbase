module Net.DNSBase.EDNS
    ( -- * Fixed portion of EDNS(0) OPT pseudo-RR
      EDNS(..)
    , defaultEDNS
    , maxUdpSize
    , minUdpSize
    ) where

import Net.DNSBase.Internal.EDNS
