{-|
Module      : Net.DNSBase.EDNS.OptNum
Description : EDNS(0) option codepoints (RFC 6891)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 16-bit @OPTION-CODE@ field used by EDNS(0) options inside
the OPT pseudo-RR
([RFC 6891 section 6.1.2](https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.2)).
Pattern synonyms cover the standardised options (NSID, ECS,
EDE, ...); unknown codes round-trip as 'Net.DNSBase.EDNS.Option.OpaqueOption' values.
See the
[IANA DNS EDNS0 Option Codes registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)
for the full list.
-}

module Net.DNSBase.EDNS.OptNum
    ( -- * EDNS(0) option numbers
      OptNum(..)
    ) where

import Net.DNSBase.EDNS.Internal.OptNum
