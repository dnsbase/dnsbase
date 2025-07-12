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

-- | [SOA RDATA](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.13).
-- Marks the start of a zone of authority, and must be present at the apex of
-- each DNS zone.  Used in negative responses and in the AXFR protocol.
-- <https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.13>
--
-- The /mname/ and /rname/ fields are subject to
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4),
-- and canonicalise to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- The 'Ord' instance is not canonical.  Canonical ordering requires
-- serialisation to canonical wire form.
--
data T_soa = T_SOA
    { soaMname   :: Domain    -- ^ Master nameserver
    , soaRname   :: Domain    -- ^ Responsible mailbox, local part is first label
    , soaSerial  :: Word32    -- ^ Zone serial number
    , soaRefresh :: Word32    -- ^ Frequency of secondary zone refresh
    , soaRetry   :: Word32    -- ^ AXFR retry interval
    , soaExpire  :: Word32    -- ^ Expiration time of stale secondary data
    , soaMinttl  :: Word32    -- ^ Negative response TTL
    } deriving (Typeable, Show)

-- | Equality is case-insensitive on the /mname/ and /rname/ fields.
instance Eq T_soa where
    a == b = (soaSerial  a) ==              (soaSerial  b)
          && (soaMname   a) `equalWireHost` (soaMname   b)
          && (soaRname   a) `equalWireHost` (soaRname   b)
          && (soaRefresh a) ==              (soaRefresh b)
          && (soaRetry   a) ==              (soaRetry   b)
          && (soaExpire  a) ==              (soaExpire  b)
          && (soaMinttl  a) ==              (soaMinttl  b)

-- | Order is case-insensitive on the /mname/ and /rname/ fields.
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
    rdType     = SOA
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
    rdDecode _ = const do
        soaMname <- getDomain
        soaRname <- getDomain
        soaSerial <- get32
        soaRefresh <- get32
        soaRetry <- get32
        soaExpire <- get32
        soaMinttl <- get32
        return $ RData T_SOA{..}

-- | [RP RData](https://www.rfc-editor.org/rfc/rfc1183.html#section-2.2)
-- Responsible person:
--
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  /                   mbox-dname                  /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  /                   txt-dname                   /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The  /mbox-dname/ is an email address, while the /txt-dname/ is a domain
-- name where one might find a @TXT@ record with alternative contact
-- information.
--
-- The /mbox-dname/ and /txt-dname/ fields are not subject to
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4),
-- on output, but accept it on input.  They canonicalise to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2),
-- [RFC6840](https://datatracker.ietf.org/doc/html/rfc6840#section-5.1).
--
-- - Equality and order are case-insensitive.
-- - The `Ord` instance is canonical.
--
data T_rp = T_RP
    { rpMbox :: Domain
    , rpTxt  :: Domain
    } deriving (Typeable, Show)

instance Eq T_rp where
    a == b = rpMbox a `equalWireHost` rpMbox b
          && rpTxt  a `equalWireHost` rpTxt  b

instance Ord T_rp where
    a `compare` b = rpMbox a `compareWireHost` rpMbox b
                 <> rpTxt  a `compareWireHost` rpTxt  b

instance Presentable T_rp where
    present T_RP{..} = present rpMbox . presentSp rpTxt

instance KnownRData T_rp where
    rdType     = RP
    rdEncode T_RP{..} = putSizedBuilder $
        mbWireForm rpMbox <> mbWireForm rpTxt
    cnEncode T_RP{..} =
        rdEncode $ T_RP (canonicalise rpMbox)
                        (canonicalise rpTxt)
    rdDecode _ = const do
        rpMbox <- getDomain
        rpTxt  <- getDomain
        return $ RData T_RP{..}
