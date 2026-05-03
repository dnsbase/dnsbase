{-|
Module      : Net.DNSBase.RData.SOA
Description : Zone administration records (SOA and RP)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

Two zone-administration RR types: 'T_soa' is the mandatory
zone-apex record describing zone serial, refresh / retry /
expire / negative-TTL timing, and the responsible operator's
mailbox.  'T_rp' is an optional record pointing at a person
responsible for a name plus a separate TXT record with free-form
contact details.
-}
{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.RData.SOA
    ( T_soa(..)
    , T_rp(..)
    ) where

import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE

-- | The @SOA@ resource record
-- ([RFC 1035 section 3.3.13](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.13))
-- — the mandatory zone-apex record carrying zone serial, refresh,
-- retry, expire, and negative-response TTL alongside the master
-- nameserver and the operator's mailbox.  Returned in negative
-- responses to convey the negative-cache TTL, and in the @AXFR@
-- zone-transfer protocol.
--
-- The mname and rname fields are subject to wire-form name
-- compression on encode
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- and canonicalise to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare the two domain fields in
-- their canonical wire form (via 'equalWireHost' /
-- 'compareWireHost') and the remaining fields in wire-encoding
-- order, so 'Ord' is canonical: it agrees with lexicographic
-- ordering of the full canonical wire form.
--
-- See 'T_rp' for the responsible-person record.
data T_soa = T_SOA
    { soaMname   :: Domain    -- ^ Master nameserver
    , soaRname   :: Domain    -- ^ Responsible mailbox, local part is first label
    , soaSerial  :: Word32    -- ^ Zone serial number
    , soaRefresh :: Word32    -- ^ Frequency of secondary zone refresh
    , soaRetry   :: Word32    -- ^ AXFR retry interval
    , soaExpire  :: Word32    -- ^ Expiration time of stale secondary data
    , soaMinttl  :: Word32    -- ^ Negative response TTL
    } deriving (Show)

-- | Equality compares the mname and rname fields in canonical
-- wire form, the remaining fields pointwise.
instance Eq T_soa where
    a == b = (soaSerial  a) ==              (soaSerial  b)
          && (soaMname   a) `equalWireHost` (soaMname   b)
          && (soaRname   a) `equalWireHost` (soaRname   b)
          && (soaRefresh a) ==              (soaRefresh b)
          && (soaRetry   a) ==              (soaRetry   b)
          && (soaExpire  a) ==              (soaExpire  b)
          && (soaMinttl  a) ==              (soaMinttl  b)

-- | Canonical: compares the mname and rname fields in canonical
-- wire form and the remaining fields in wire-encoding order, so
-- the result matches lexicographic comparison of the canonical
-- wire form.
instance Ord T_soa where
    a `compare` b = (soaMname   a) `compareWireHost` (soaMname   b)
                 <> (soaRname   a) `compareWireHost` (soaRname   b)
                 <> (soaSerial  a) `compare`         (soaSerial  b)
                 <> (soaRefresh a) `compare`         (soaRefresh b)
                 <> (soaRetry   a) `compare`         (soaRetry   b)
                 <> (soaExpire  a) `compare`         (soaExpire  b)
                 <> (soaMinttl  a) `compare`         (soaMinttl  b)

instance Presentable T_soa where
    present T_SOA{..} =
        present     soaMname
        . presentSp soaRname
        . presentSp soaSerial
        . presentSp soaRefresh
        . presentSp soaRetry
        . presentSp soaExpire
        . presentSp soaMinttl

instance KnownRData T_soa where
    rdType _ = SOA
    {-# INLINE rdType #-}
    rdEncode T_SOA{..}= do
        putDomain soaMname
        putDomain soaRname
        putSizedBuilder $
               mbWord32 soaSerial
            <> mbWord32 soaRefresh
            <> mbWord32 soaRetry
            <> mbWord32 soaExpire
            <> mbWord32 soaMinttl
    cnEncode T_SOA{..} = putSizedBuilder $
           mbWireForm (canonicalise soaMname)
        <> mbWireForm (canonicalise soaRname)
        <> mbWord32 soaSerial
        <> mbWord32 soaRefresh
        <> mbWord32 soaRetry
        <> mbWord32 soaExpire
        <> mbWord32 soaMinttl
    rdDecode _ _ = const do
        soaMname <- getDomain
        soaRname <- getDomain
        soaSerial <- get32
        soaRefresh <- get32
        soaRetry <- get32
        soaExpire <- get32
        soaMinttl <- get32
        return $ RData T_SOA{..}

-- | The @RP@ resource record
-- ([RFC 1183 section 2.2](https://www.rfc-editor.org/rfc/rfc1183.html#section-2.2))
-- — the responsible person for a name: an mbox-dname encoding an
-- email address (the first label is the local part, per the
-- usual DNS mailbox-name convention), and a txt-dname pointing
-- at a 'Net.DNSBase.RData.TXT.T_txt' record with free-form contact details.
--
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  /                   mbox-dname                  /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  /                   txt-dname                   /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- Neither field is wire-form name-compressed on encode
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- but compression is tolerated on decode.  Both fields
-- canonicalise to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2),
-- [RFC 6840 section 5.1](https://datatracker.ietf.org/doc/html/rfc6840#section-5.1)).
-- The 'Eq' and 'Ord' instances compare both fields in canonical
-- wire form (via 'equalWireHost' / 'compareWireHost'); since the
-- field order matches the wire encoding, 'Ord' is canonical.
--
-- See 'T_soa' for the mandatory zone-apex record.
data T_rp = T_RP
    { rpMbox :: Domain
    , rpTxt  :: Domain
    } deriving (Show)

instance Eq T_rp where
    a == b = rpMbox a `equalWireHost` rpMbox b
          && rpTxt  a `equalWireHost` rpTxt  b

instance Ord T_rp where
    a `compare` b = rpMbox a `compareWireHost` rpMbox b
                 <> rpTxt  a `compareWireHost` rpTxt  b

instance Presentable T_rp where
    present T_RP{..} = present rpMbox . presentSp rpTxt

instance KnownRData T_rp where
    rdType _ = RP
    rdEncode T_RP{..} = putSizedBuilder $
        mbWireForm rpMbox <> mbWireForm rpTxt
    cnEncode T_RP{..} =
        rdEncode $ T_RP (canonicalise rpMbox)
                        (canonicalise rpTxt)
    rdDecode _ _ = const do
        rpMbox <- getDomain
        rpTxt  <- getDomain
        return $ RData T_RP{..}
