{-# LANGUAGE RecordWildCards #-}
module Net.DNSBase.Internal.RR
    ( RR(..)
    , putRR
    , rrDataCast
    , rrType
    ) where

import Net.DNSBase.Encode.Internal.Metric
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.Domain (Domain, equalWireHost)
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.RRCLASS
import Net.DNSBase.Internal.Util

-- | DNS Resource Record [RFC1035 3.2.1](https://tools.ietf.org/html/rfc1035#section-3.2.1)
--
-- >                                 1  1  1  1  1  1
-- >   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                                               |
-- > /                                               /
-- > /                      NAME                     /
-- > |                                               |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                      TYPE                     |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                     CLASS                     |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                      TTL                      |
-- > |                                               |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                   RDLENGTH                    |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
-- > /                     RDATA                     /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The @TYPE@ field is implicit in the polymorphic 'rrData'.
--
data RR = RR
    { rrOwner :: Domain
    , rrClass :: RRCLASS
    , rrTTL   :: Word32
    , rrData  :: RData
    } deriving (Show)

instance Eq RR where
    a == b = rrOwner a `equalWireHost` rrOwner b
          && rrClass a ==              rrClass b
          && rrTTL   a ==              rrTTL   b
          && rrData  a ==              rrData  b

instance Presentable RR where
    present RR{..} =
        present rrOwner
        . presentSp rrTTL
        . presentSp rrClass
        . presentSp rrData

putRR :: RR -> SPut s RData
putRR RR{..} = do
    putDomain rrOwner
    putSizedBuilder $!
        mbWord16 (coerce $ rdataType rrData)
        <> mbWord16 (coerce rrClass)
        <> mbWord32 rrTTL
    passLen $ rdataEncode rrData

-- | Attempt to cast the 'RData' payload of an 'RR' to a 'KnownRData' type,
-- obtaining its type-specific representation.  Returns 'Nothing' if the types
-- do not match.
--
-- Note that /opaque/ 'RData' payloads can't be cast directly to type-specific
-- forms, instead their content has to be explicitly decoded.
rrDataCast :: KnownRData a => RR -> Maybe a
rrDataCast = fromRData . rrData
{-# INLINE rrDataCast #-}

-- | Returns the 'RRTYPE' of the 'RData' payload of the 'RR'.
rrType :: RR -> RRTYPE
rrType = rdataType . rrData
