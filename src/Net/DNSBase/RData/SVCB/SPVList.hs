module Net.DNSBase.RData.SVCB.SPVList
    ( presentSPVList
    ) where

import Net.DNSBase.Internal.Util

import Net.DNSBase.Text

presentSPVList :: (NonEmpty ShortByteString) -> Builder -> Builder
presentSPVList (v :| vs) = presentCSVList (v : vs)
