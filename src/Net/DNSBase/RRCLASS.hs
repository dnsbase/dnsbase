{-|
Module      : Net.DNSBase.RRCLASS
Description : DNS resource record CLASS values (RFC 1035 section 3.2.4)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 16-bit @CLASS@ field of a DNS resource record.  In modern
practice essentially everything uses 'IN' (Internet); the other
registered values ('CHAOS', 'HESIOD', 'NONE', 'ANYCLASS') are
historic or have specialised uses.  See the
[IANA DNS Classes registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2)
for the full list.
-}

module Net.DNSBase.RRCLASS
    ( -- * DNS resource class numbers
      RRCLASS(..)
    ) where

import Net.DNSBase.Internal.RRCLASS
