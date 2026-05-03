{-|
Module      : Net.DNSBase.Message
Description : The DNS message container type and wire-form encoders
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

A 'DNSMessage' is the full DNS-protocol packet
([RFC 1035 section 4.1](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1)):
a 16-bit query identifier, the flag word, and four sections
(question, answer, authority, additional) carrying the associated
'Net.DNSBase.RR.RR' lists.  The lookup functions return either a
whole 'DNSMessage' (via 'Net.DNSBase.Lookup.lookupRaw' /
'Net.DNSBase.Lookup.lookupRawCtl') or just the filtered answer
'Net.DNSBase.RR.RR' list (via 'Net.DNSBase.Lookup.lookupAnswers'
and the per-RR-type lookups).

'putMessage' and 'putRequest' are the wire-format encoders.
Applications building responses use 'putMessage' directly;
'putRequest' is the stub-resolver path used by
"Net.DNSBase.Internal.Transport".
-}

module Net.DNSBase.Message
    ( -- * DNS Message data type
      DNSMessage(..)
    , QueryID
    , putMessage
    , putRequest
    ) where

import Net.DNSBase.Internal.Message
