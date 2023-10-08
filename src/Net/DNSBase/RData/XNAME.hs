module Net.DNSBase.RData.XNAME
    ( -- * RR types representing a single domain name
      X_domain(T_NS, T_PTR, T_CNAME)
    , T_ns
    , T_ptr
    , T_cname
    , T_dname(..)
    ) where

import Net.DNSBase.RData.Internal.XNAME
