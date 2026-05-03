{-|
Module      : Net.DNSBase.Flags
Description : DNS message header flags and resolver flag-control building blocks
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 'DNSFlags' field of a 'Net.DNSBase.Message.DNSMessage' carries the genuine
/flag/ bits from the basic DNS header
([RFC 1035 section 4.1.1](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1))
— QR, AA, TC, RD, RA, Z, AD, CD: eight bits in total, of which
Z must be zero per the protocol, leaving seven in practical
use — plus the extended flag bits that arrive in the OPT
pseudo-RR
([RFC 6891 section 6.1.4](https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.4)),
chiefly the DO bit.  The OPCODE and RCODE fields of the header
are masked out of 'DNSFlags' and carried separately in the
'Net.DNSBase.Message.DNSMessage' record.

The 'FlagOps' machinery is the building block resolver
'Net.DNSBase.Resolver.QueryControls' uses for per-call flag tweaks: 'setFlagBits' /
'clearFlagBits' / 'resetFlagBits' build endomorphisms that the
resolver applies to its default outgoing flags, so callers
specify only the bits they want to change rather than the
whole flag word.
-}

module Net.DNSBase.Flags
    ( -- * DNS Message basic and extended flags
      DNSFlags(..)
    -- * DNS flag construction and inspection
    , basicFlags
    , extendFlags
    , extendedFlags
    , hasAllFlags
    , hasAnyFlags
    , makeDNSFlags
    , maskDNSFlags
    -- * Resolver flag control building blocks
    , FlagOps
    , setFlagBits
    , clearFlagBits
    , resetFlagBits
    , emptyFlagOps
    , applyFlagOps
    ) where

import Net.DNSBase.Internal.Flags
