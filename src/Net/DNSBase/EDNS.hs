{-|
Module      : Net.DNSBase.EDNS
Description : Fixed part of the EDNS(0) OPT pseudo-RR
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

'EDNS' carries the non-option parts of the OPT pseudo-RR
([RFC 6891 section 6.1.3](https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.3)):
the advertised UDP payload size, EDNS version, extended-RCODE
bits, and the DO (DNSSEC-OK) flag, along with the option list
itself.  'defaultEDNS' is the resolver's default configuration;
'minUdpSize' and 'maxUdpSize' are the clamps applied when a
caller overrides the payload size via 'Net.DNSBase.Resolver.EdnsUdpSize'.
-}

module Net.DNSBase.EDNS
    ( -- * Fixed portion of EDNS(0) OPT pseudo-RR
      EDNS(..)
    , defaultEDNS
    , maxUdpSize
    , minUdpSize
    ) where

import Net.DNSBase.Internal.EDNS
