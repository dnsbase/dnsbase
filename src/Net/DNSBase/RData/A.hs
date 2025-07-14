module Net.DNSBase.RData.A
    ( T_a(..)
    , T_aaaa(..)
    , IP
    , IPv4
    , IPv6
    , evalIP
    ) where

import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE


-- | [A RDATA](https://tools.ietf.org/html/rfc1035#section-3.4.1).
-- Host IPv4 address.
--
-- Ordered canonically:
-- [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)
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


-- | [AAAA RDATA: IPv6 address](https://tools.ietf.org/html/rfc3596#section-2.1).
-- Host IPv6 address.
--
-- Ordered canonically:
-- [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)
newtype T_aaaa = T_AAAA IPv6 -- ^ IPv6 address
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


-- | Evaluate the given function at either an IPv4 or IPv6 address 'RData',
-- returning 'Just' the result, or 'Nothing' otherwise.
evalIP :: (IP -> a) -> RData -> Maybe a
evalIP f (fromRData -> Just (T_A ip))    = Just $ f (IPv4 ip)
evalIP f (fromRData -> Just (T_AAAA ip)) = Just $ f (IPv6 ip)
evalIP _ _                                    = Nothing
