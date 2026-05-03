{-|
Module      : Net.DNSBase.RData.CSYNC
Description : Child-to-parent signalling records (CSYNC and DSYNC)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

Two unrelated child-to-parent signalling RR types live here.
'T_csync' (RFC 7477) tells the parent zone which delegation
records the child wishes to have synchronized; 'T_dsync'
(generalised DNS notifications, draft-ietf-dnsop-generalized-notify)
advertises the per-RR-type endpoints a child operator wishes
the parent to send notifications to.  They share neither wire
format nor purpose beyond the broad child-to-parent direction.
-}
{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.RData.CSYNC
    ( -- * CSYNC RData
      T_csync(..)
    , NsecTypes
    , nsecTypesFromList
    , nsecTypesToList
    , hasRRtype
      -- * DSYNC RData
    , T_dsync(..)
    , Dscheme(.., NOTIFY)
    ) where

import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.State
import Net.DNSBase.NsecTypes
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE

-----------------

-- | The @CSYNC@ resource record
-- ([RFC 7477 section 2.1.1](https://www.rfc-editor.org/rfc/rfc7477.html#section-2.1.1))
-- — the child zone's request to its parent to synchronise NS / A /
-- AAAA records from the child to the parent.  Three fields: the
-- child's current SOA serial, processing flags, and an 'NsecTypes'
-- bitmap naming the RR types to be synchronised.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                          SOA Serial                           |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |       Flags                   |            Type Bit Map       /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > /                     Type Bit Map (continued)                  /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- See 'T_dsync' for the other child-to-parent signalling RR type
-- defined in this module.
data T_csync = T_CSYNC
    { csyncSerial :: Word32    -- ^ Zone serial number
    , csyncFlags  :: Word16    -- ^ flag Bits
    , csyncTypes  :: NsecTypes -- ^ Type Bitmap
    } deriving (Eq, Show)

instance Ord T_csync where
    a `compare` b = csyncSerial a `compare` csyncSerial b
                 <> csyncFlags  a `compare` csyncFlags  b
                 <> csyncTypes  a `compare` csyncTypes  b

instance Presentable T_csync where
    present T_CSYNC{..} =
        present     csyncSerial
        . presentSp csyncFlags
        . presentSp csyncTypes

instance KnownRData T_csync where
    rdType _ = CSYNC
    {-# INLINE rdType #-}
    rdEncode T_CSYNC{..} = do
        putSizedBuilder $
           mbWord32 csyncSerial
           <> mbWord16 csyncFlags
        putNsecTypes csyncTypes
    rdDecode _ _ len = do
        csyncSerial <- get32
        csyncFlags  <- get16
        csyncTypes <- getNsecTypes (len - 6)
        pure $ RData T_CSYNC{..}

-----------------

-- | DSYNC scheme numbers.  The 'Presentable' instance displays the registered
-- mnemonic of the scheme name for known types, or else just the decimal value.
-- See the
-- [IANA registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dsync-location-of-synchronization-endpoints)
-- for the known mnemonics.
--
newtype Dscheme = DSCHEME Word8
    deriving newtype ( Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read )

-- | [NOTIFY scheme](https://datatracker.ietf.org/doc/html/rfc9859#section-6.2).
pattern NOTIFY      :: Dscheme;     pattern NOTIFY         = DSCHEME 1

instance Presentable Dscheme where
    present NOTIFY       = present @String "NOTIFY"
    present (DSCHEME n)  = present n


-- | The @DSYNC@ resource record
-- ([RFC 9859](https://datatracker.ietf.org/doc/html/rfc9859#section-2.1))
-- — a child zone's published endpoint for generalised DNS
-- notifications: for a given child-side 'RRTYPE', it names the
-- 'Dscheme' (contact method, e.g.\ 'NOTIFY'), the contact 'Word16'
-- port number, and the 'Domain' to address the notification to.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > | RRtype                        | Scheme        | Port
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >                 | Target ...  /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
--
-- See 'T_csync' for the other child-to-parent signalling RR type
-- defined in this module.
--
-- Target comparison and equality are case-sensitive.
-- The 'Ord' instance is canonical.
data T_dsync = T_DSYNC
    { dsyncRRtype :: RRTYPE    -- ^ Supported notification type
    , dsyncScheme :: Dscheme   -- ^ Contact mode
    , dsyncPort   :: Word16    -- ^ Contact port
    , dsyncTarget :: Domain    -- ^ Server hostname
    } deriving (Eq, Show)

instance Ord T_dsync where
    a `compare` b = dsyncRRtype a `compare` dsyncRRtype b
                 <> dsyncScheme a `compare` dsyncScheme b
                 <> dsyncPort   a `compare` dsyncPort   b
                 <> dsyncTarget a `compare` dsyncTarget b

instance Presentable T_dsync where
    present T_DSYNC{..} =
        present     dsyncRRtype
        . presentSp dsyncScheme
        . presentSp dsyncPort
        . presentSp dsyncTarget

instance KnownRData T_dsync where
    rdType _ = DSYNC
    {-# INLINE rdType #-}
    rdEncode T_DSYNC{..} = putSizedBuilder $
        mbWord16 (coerce dsyncRRtype)
        <> mbWord8 (coerce dsyncScheme)
        <> mbWord16 dsyncPort
        <> mbWireForm dsyncTarget
    rdDecode _ _ _ = do
        dsyncRRtype <- RRTYPE <$> get16
        dsyncScheme <- DSCHEME <$> get8
        dsyncPort   <- get16
        dsyncTarget <- getDomainNC
        pure $ RData T_DSYNC{..}
