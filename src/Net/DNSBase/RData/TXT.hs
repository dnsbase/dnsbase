{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.RData.TXT
    ( T_txt(..)
    , T_hinfo(..)
    , T_null(..)
    ) where

import qualified Data.ByteString.Short as SB

import Net.DNSBase.Internal.Util

import Net.DNSBase.Bytes
import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE
import Net.DNSBase.Text

-- | [TXT RDATA](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14).
--
-- This is a list of strings of 8-bit bytes, each at most 255 bytes in length.
-- In most applications the individual strings should just be concatenated
-- together without inserting intermediate whitespace.  In less common
-- applications the strings may carry separate meaning, and are treated as
-- separate data items.
--
-- While the constructor does not enforce the length limits, attempts to
-- encode a TXT RR with overly long substrings will fail encoding to wire
-- form.  TXT records decoded from wire form are guaranteed to not exceed the
-- length limit.
--
newtype T_txt = T_TXT (NonEmpty ShortByteString) -- ^ Some character-strings
    deriving (Eq, Show)

instance Ord T_txt where
    compare = comparing asDnsText
      where
        asDnsText :: T_txt -> NonEmpty DnsText
        asDnsText = coerce

instance Presentable T_txt where
    present (T_TXT (str :| strs)) =
        pfst str
        . flip (foldr pnxt) strs
      where
        pfst = present @DnsText . coerce
        pnxt = presentSp @DnsText . coerce

instance KnownRData T_txt where
    rdType _ = TXT
    {-# INLINE rdType #-}
    rdEncode (T_TXT strs) =
        mapM_ encodeCharString strs
    rdDecode _ _ len = do
        pos0 <- getPosition
        str  <- getShortByteStringLen8
        used <- subtract pos0 <$> getPosition
        rest <- getVarWidthSequence getShortByteStringLen8 (len - used)
        pure $ RData $ T_TXT $ str :| rest

-- | [HINFO RDATA](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.2)
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                      CPU                      /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                       OS                      /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The 'Ord' instance is canonical.
--
data T_hinfo = T_HINFO
    { hinfoCPU :: ShortByteString
    , hinfoOS  :: ShortByteString
    } deriving (Eq, Show)

instance Ord T_hinfo where
    a `compare` b = hinfoCPU a `strCompare` hinfoCPU b
                 <> hinfoOS  a `strCompare` hinfoOS  b
      where
        strCompare = comparing DnsText

instance Presentable T_hinfo where
    present T_HINFO{..} =
        present     @DnsText (coerce hinfoCPU)
        . presentSp @DnsText (coerce hinfoOS)

instance KnownRData T_hinfo where
    rdType _ = HINFO
    {-# INLINE rdType #-}
    rdEncode T_HINFO{..} = do
        encodeCharString hinfoCPU
        encodeCharString hinfoOS
    rdDecode _ _ = const do
        RData <$.> T_HINFO <$> getShortByteStringLen8 <*> getShortByteStringLen8

-- | [NULL RDATA](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.10)
-- Anything at all may be in the RDATA field so long as it is 65535 octets or
-- less.  Presented as a haxadecimal string.
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                  <anything>                   /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- Ordered canonically:
-- [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)
--
newtype T_null = T_NULL Bytes16
    deriving (Eq, Ord, Show)

instance Presentable T_null where
    present (T_NULL val) =
        present @String "\\# "
        . present (SB.length $ coerce val)
        . presentSp val

instance KnownRData T_null where
    rdType _ = NULL
    {-# INLINE rdType #-}
    rdEncode = putShortByteString . coerce
    rdDecode _ _ = RData . T_NULL . coerce <.> getShortNByteString

--------------

-- | Encode a DNS /character-string/ (explicit one byte length).
encodeCharString :: ShortByteString -> SPut s RData
encodeCharString = putShortByteStringLen8
