{-|
Module      : Net.DNSBase.Opcode
Description : DNS message OPCODE values (RFC 1035 section 4.1.1)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 4-bit @OPCODE@ field of a DNS message header — usually
@QUERY@ for ordinary lookups, with @IQUERY@, @STATUS@,
@NOTIFY@, and @UPDATE@ for less common message kinds.  See the
[IANA DNS Operation Codes registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5)
for the full list.
-}

module Net.DNSBase.Opcode
    ( -- * DNS request and reply OPCODE numbers
      Opcode(..)
    ) where

import Net.DNSBase.Internal.Opcode
