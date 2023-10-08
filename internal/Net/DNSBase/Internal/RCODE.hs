module Net.DNSBase.Internal.RCODE
    ( RCODE
        ( RCODE
        , NOERROR
        , FORMERR
        , SERVFAIL
        , NXDOMAIN
        , NOTIMP
        , REFUSED
        , YXDOMAIN
        , YXRRSET
        , NXRRSET
        , NOTAUTH
        , NOTZONE
        , DSOTYPENI
        , BADVERS
        , BADSIG
        , BADKEY
        , BADTIME
        , BADMODE
        , BADNAME
        , BADALG
        , BADTRUNC
        , BADCOOKIE
        )
    , extendRCODE
    ) where

import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

-- | The extended (12-bit) DNS RCODE consisting of 4 bits from the basic DNS
-- header, possibly augmented with 8 more bits from the EDNS header.
--
-- Should always be zero in well-formed requests.  When decoding replies, the
-- high eight bits from any EDNS response are combined with the 4-bit RCODE
-- from the DNS header.  When encoding a message, if EDNS is disabled RCODE
-- values larger than 15 are mapped to 'FormatErr'.  The same applies to
-- values larger than 4095 whether EDNS is used or not.
--
newtype RCODE = RC_ Word16 deriving (Eq, Ord, Enum, Show)

instance Bounded RCODE where
    minBound = RC_ 0
    maxBound = RC_ 0xfff

{-# COMPLETE RCODE #-}
pattern RCODE :: Word16 -> RCODE
pattern RCODE w <- RC_ w where
    RCODE w
        | RC_ w <= maxBound = RC_ w
        | otherwise         = error "RCODE out of range"

-- | Combine basic header RCODE (low 4 bits)
--     with EDNS extended RCODE (high 8 bits)
extendRCODE :: RCODE -> Word8 -> RCODE
extendRCODE (RCODE lo) hi =
    RCODE $ (fromIntegral hi `shiftL` 4) .|. (lo .&. 0xF)


instance Presentable RCODE where
    present NOERROR    = present @String "NOERROR"
    present FORMERR    = present @String "FORMERR"
    present SERVFAIL   = present @String "SERVFAIL"
    present NXDOMAIN   = present @String "NXDOMAIN"
    present NOTIMP     = present @String "NOTIMP"
    present REFUSED    = present @String "REFUSED"
    present YXDOMAIN   = present @String "YXDOMAIN"
    present YXRRSET    = present @String "YXRRSET"
    present NXRRSET    = present @String "NXRRSET"
    present NOTAUTH    = present @String "NOTAUTH"
    present NOTZONE    = present @String "NOTZONE"
    present DSOTYPENI  = present @String "DSOTYPENI"
    present BADVERS    = present @String "BADVERS"
    present BADSIG     = present @String "BADSIG"
    present BADKEY     = present @String "BADKEY"
    present BADTIME    = present @String "BADTIME"
    present BADMODE    = present @String "BADMODE"
    present BADNAME    = present @String "BADNAME"
    present BADALG     = present @String "BADALG"
    present BADTRUNC   = present @String "BADTRUNC"
    present BADCOOKIE  = present @String "BADCOOKIE"
    present (RC_ rc)   = present @String "RCODE" . present rc

------------------------------------------

-- NOERROR - [RFC1035]
pattern NOERROR :: RCODE
pattern NOERROR = RCODE 0

-- FORMERR - [RFC1035]
pattern FORMERR :: RCODE
pattern FORMERR = RCODE 1

-- SERVFAIL - [RFC1035]
pattern SERVFAIL :: RCODE
pattern SERVFAIL = RCODE 2

-- | NXDOMAIN - [RFC1035]
pattern NXDOMAIN     :: RCODE
pattern NXDOMAIN     = RCODE 3

-- | NOTIMP - [RFC1035]
pattern NOTIMP       :: RCODE
pattern NOTIMP       = RCODE 4

-- | REFUSED - [RFC1035]
pattern REFUSED      :: RCODE
pattern REFUSED      = RCODE 5

-- | YXDOMAIN - [RFC2136][RFC6672]
pattern YXDOMAIN     :: RCODE
pattern YXDOMAIN     = RCODE 6

-- | YXRRSET - [RFC2136]
pattern YXRRSET      :: RCODE
pattern YXRRSET      = RCODE 7

-- | NXRRSET - [RFC2136]
pattern NXRRSET      :: RCODE
pattern NXRRSET      = RCODE 8

-- | NOTAUTH - [RFC2136]
pattern NOTAUTH      :: RCODE
pattern NOTAUTH      = RCODE 9

-- | NOTZONE - [RFC2136]
pattern NOTZONE      :: RCODE
pattern NOTZONE      = RCODE 10

-- | DSOTYPENI - [RFC8490]
pattern DSOTYPENI    :: RCODE
pattern DSOTYPENI    = RCODE 11

-- | RCODES 12 through 15 are reserved, see
-- [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6)
--
-- BADVERS - [RFC6891]
pattern BADVERS      :: RCODE
pattern BADVERS      = RCODE 16

-- | BADSIG - [RFC2845]
pattern BADSIG       :: RCODE
pattern BADSIG       = RCODE 16

-- | BADKEY - [RFC2845]
pattern BADKEY       :: RCODE
pattern BADKEY       = RCODE 17

-- | BADTIME - [RFC2845]
pattern BADTIME      :: RCODE
pattern BADTIME      = RCODE 18

-- | BADMODE - [RFC2930]
pattern BADMODE      :: RCODE
pattern BADMODE      = RCODE 19

-- | BADNAME - [RFC2930]
pattern BADNAME      :: RCODE
pattern BADNAME      = RCODE 20

-- | BADALG - [RFC2930]
pattern BADALG       :: RCODE
pattern BADALG       = RCODE 21

-- | BADTRUNC - [RFC4635]
pattern BADTRUNC     :: RCODE
pattern BADTRUNC     = RCODE 22

-- | BADCOOKIE - [RFC7873]
pattern BADCOOKIE    :: RCODE
pattern BADCOOKIE    = RCODE 23
