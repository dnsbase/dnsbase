{-|
Module      : Net.DNSBase.RCODE
Description : DNS message response codes (RFC 1035, RFC 6891)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The RCODE that the server returns in a DNS response.  The
original RCODE was a 4-bit field in the DNS header
([RFC 1035 section 4.1.1](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1));
EDNS extends it to 12 bits via the @EXTENDED-RCODE@ field of
the OPT pseudo-RR
([RFC 6891 section 6.1.3](https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.3)).
See the
[IANA DNS RCODEs registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6)
for the full list.
-}

module Net.DNSBase.RCODE
    ( -- * DNS Message response codes
      RCODE(..)
    ) where

import Net.DNSBase.Internal.RCODE
