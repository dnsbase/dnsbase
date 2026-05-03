{-|
Module      : Net.DNSBase.RData.A
Description : Address records (A and AAAA)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The two address RR types parallel the variants of 'Data.IP.IP':
'T_a' wraps the @A@ RR's 'IPv4' payload, 'T_aaaa' wraps the
@AAAA@ RR's 'IPv6' payload.  Construct or destructure via the
@T_A@ / @T_AAAA@ pattern constructors.  When working with a
polymorphic 'RData' value that may be either, 'evalIP'
dispatches on whichever applies and lifts the address into the
common 'Data.IP.IP' sum.
-}

module Net.DNSBase.RData.A
    ( T_a(..)
    , T_aaaa(..)
    , evalIP
    ) where
import Data.IP (IP(..), IPv4, IPv6)

import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE
import Net.DNSBase.Internal.Util (showsP)

-- | The @A@ resource record
-- ([RFC 1035 section 3.4.1](https://tools.ietf.org/html/rfc1035#section-3.4.1))
-- — a 32-bit IPv4 address transmitted as four bytes in network
-- order.  The derived 'Ord' is numeric 'IPv4' order, which agrees
-- with canonical RR-content ordering
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
--
-- See 'T_aaaa' for the IPv6-family parallel, and 'evalIP' for a
-- helper that handles either uniformly.
newtype T_a = T_A IPv4 -- ^ 'IPv4' address
    deriving (Eq, Ord, Enum)

instance Show T_a where
    showsPrec p (T_A a) = showsP p $
        showString "T_A \"" . shows a . showChar '"'

instance Presentable T_a where
    present (T_A a) = present a

instance KnownRData T_a where
    rdType _ = A
    {-# INLINE rdType #-}
    rdEncode (T_A ip4) = putIPv4 ip4
    rdDecode _ _ = const do RData . T_A <$> getIPv4


-- | The @AAAA@ resource record
-- ([RFC 3596 section 2.1](https://tools.ietf.org/html/rfc3596#section-2.1))
-- — a 128-bit IPv6 address transmitted as sixteen bytes in network
-- order.  The derived 'Ord' is numeric 'IPv6' order, which agrees
-- with canonical RR-content ordering
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
--
-- See 'T_a' for the IPv4-family parallel, and 'evalIP' for a
-- helper that handles either uniformly.
newtype T_aaaa = T_AAAA IPv6 -- ^ 'IPv6' address
    deriving (Eq, Ord)

instance Show T_aaaa where
    showsPrec p (T_AAAA a) = showsP p $
        showString "T_AAAA \"" . shows a . showChar '"'

instance Presentable T_aaaa where
    present (T_AAAA a) = present a

instance KnownRData T_aaaa where
    rdType _ = AAAA
    {-# INLINE rdType #-}
    rdEncode (T_AAAA ip6) = putIPv6 ip6
    rdDecode _ _ = const do RData . T_AAAA <$> getIPv6


-- | Apply the supplied function to whichever IP address an 'RData'
-- carries, lifting the 'T_a' or 'T_aaaa' payload into the unified
-- 'Data.IP.IP' sum.  Returns 'Nothing' for 'RData' of any other type.
--
-- > evalIP id (RData (T_A    ip)) == Just (IPv4 ip)
-- > evalIP id (RData (T_AAAA ip)) == Just (IPv6 ip)
evalIP :: (IP -> a) -> RData -> Maybe a
evalIP f (fromRData -> Just (T_A ip))    = Just $! f (IPv4 ip)
evalIP f (fromRData -> Just (T_AAAA ip)) = Just $! f (IPv6 ip)
evalIP _ _                               = Nothing
