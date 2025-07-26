{-# LANGUAGE
    PatternSynonyms
  , RecordWildCards
  #-}

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

-- | [CSYNC RDATA](https://www.rfc-editor.org/rfc/rfc7477.html#section-2.1.1)
-- Used in child-to-parent signalling.
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
        present          csyncSerial
        . presentSp      csyncFlags
        . presentSpTypes csyncTypes

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
-- See the [IANA registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dsync-location-of-synchronization-endpoints)
-- for the known mnemonics.
--
newtype Dscheme = DSCHEME Word8
    deriving newtype ( Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read )

-- | [IP4 address](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern NOTIFY      :: Dscheme;     pattern NOTIFY         = DSCHEME 1

instance Presentable Dscheme where
    present NOTIFY       = present @String "NOTIFY"
    present (DSCHEME n)  = present n


-- | [DSYNC RDATA](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-generalized-notify-09#name-dsync-rr-type)
-- Generalized DNS Notifications.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > | RRtype                        | Scheme        | Port
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >                 | Target ...  /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
--
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
