{-|
Module      : Net.DNSBase.RData.TXT
Description : Text-payload RR types (TXT, HINFO, NULL)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

Three RFC 1035 RR types carrying byte-string payloads.
'T_txt' is the general-purpose record holding one or more
character-strings — used by SPF, DKIM, DMARC, and many ad-hoc
TXT conventions.  'T_hinfo' was defined to describe a host's
hardware and operating system but is rarely used in modern zone
data.  'T_null' is opaque arbitrary bytes; primarily a
historical placeholder, presented using the generic RFC 3597
syntax.
-}
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

-- | The @TXT@ resource record
-- ([RFC 1035 section 3.3.14](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14))
-- — a non-empty list of byte-strings, each at most 255 bytes long.
-- Most TXT-record conventions (SPF, DKIM, DMARC, ...) concatenate
-- the strings on read, but the wire format preserves the boundaries.
--
-- The constructor does not enforce the per-string 255-byte limit;
-- encoding fails if any individual string exceeds it.  Values
-- decoded from wire form are always within the limit by
-- construction.
--
-- The 'Ord' instance compares the strings as DNS
-- character-strings (length-prefixed lexicographic), agreeing
-- with the canonical wire-form ordering of
-- [RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
newtype T_txt = T_TXT (NonEmpty ShortByteString) -- ^ One or more character-strings
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

-- | The @HINFO@ resource record
-- ([RFC 1035 section 3.3.2](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.2))
-- — host information: a /CPU/ character-string and an /OS/
-- character-string describing the named host's hardware and
-- operating system.  Rarely used in modern zone data; RFC 8482
-- reuses the type code as a placeholder answer for @ANY@ queries.
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                      CPU                      /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                       OS                      /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The 'Ord' instance compares both fields as DNS
-- character-strings, giving canonical ordering
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
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

-- | The @NULL@ resource record
-- ([RFC 1035 section 3.3.10](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.10))
-- — arbitrary opaque bytes (up to 65535).  Rarely seen on the
-- wire; presented using the generic
-- [RFC 3597 section 5](https://datatracker.ietf.org/doc/html/rfc3597#section-5)
-- syntax (@\\\# /n/ /hex/@).
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                  <anything>                   /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- Derived 'Ord' is canonical
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
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
