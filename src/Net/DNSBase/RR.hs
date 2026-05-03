{-|
Module      : Net.DNSBase.RR
Description : The DNS resource-record container type
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

An 'RR' value is the standard DNS resource record: an owner name,
a class, a type, a TTL, and an 'Net.DNSBase.RData.RData' payload.
The payload is held inside the existential
'Net.DNSBase.RData.RData' wrapper, so a single 'RR' value can
carry any registered RR type's data.  Use 'rrDataCast' to recover
a specific 'Net.DNSBase.RData.KnownRData' value from the wrapper;
the 'Net.DNSBase.RData.fromRData' / 'Net.DNSBase.RData.monoRData'
/ 'Net.DNSBase.RData.rdataType' helpers re-exported from
"Net.DNSBase.RData" do the same on 'Net.DNSBase.RData.RData'
directly.
-}

module Net.DNSBase.RR
    ( -- * DNS resource record data type
      RR(..)
    , putRR
    , rrDataCast
    , rrType
    ) where

import Net.DNSBase.Internal.RR
