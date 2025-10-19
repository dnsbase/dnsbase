{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.RData.SRV
    ( T_mx(..)
    , T_srv(..)
    , T_afsdb(..)
    , T_naptr(..)
    , T_amtrelay(..)
    , AmtRelay(Amt_Nil, Amt_A, Amt_AAAA, Amt_Host, Amt_Opaque)
    ) where

import qualified Data.ByteString.Short as SB
import Data.ByteString.Builder (word8HexFixed)

import Net.DNSBase.Internal.Util
import Net.DNSBase.Internal.Bytes

import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE
import Net.DNSBase.Text

-- | [MX RDATA](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.9).
--
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  |                  PREFERENCE                   |
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  /                   EXCHANGE                    /
-- >  /                                               /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- Names that resolve to a CNAME should be avoided in the /exchange/ field
-- of MX records:
-- <https://datatracker.ietf.org/doc/html/rfc2181#section-10.3>,
-- <https://datatracker.ietf.org/doc/html/rfc5321#section-5.1>.
--
-- The exchange field name is subject to name compression:
-- <https://datatracker.ietf.org/doc/html/rfc3597#section-4>
-- and canonicalises to lower case:
-- <https://datatracker.ietf.org/doc/html/rfc4034#section-6.2>.
--
-- Ordered canonically.
--
data T_mx = T_MX
    { mxPref :: Word16 -- ^ Preference, lower is better
    , mxExch :: Domain -- ^ Exchange host.
    } deriving (Show)

-- | Case-insensitive wire-form equality.
instance Eq T_mx where
    a == b = (mxPref a) ==              (mxPref b)
          && (mxExch a) `equalWireHost` (mxExch b)

-- | Case-insensitive wire-form order.
instance Ord T_mx where
    compare a b = (mxPref a) `compare`         (mxPref b)
               <> (mxExch a) `compareWireHost` (mxExch b)

instance Presentable T_mx where
    present T_MX{..} = present mxPref . presentSp mxExch

instance KnownRData T_mx where
    rdType _ = MX
    {-# INLINE rdType #-}
    rdEncode T_MX{..} = do
        put16 mxPref
        -- Subject to name compression.
        putDomain mxExch
    cnEncode T_MX{..} = putSizedBuilder $
        mbWord16 mxPref
        <> mbWireForm (canonicalise mxExch)
    rdDecode _ _ = const do
        mxPref <- get16
        -- Subject to name compression.
        mxExch <- getDomain
        return $ RData $ T_MX{..}

-- | [SRV RDATA](https://datatracker.ietf.org/doc/html/rfc2782).
-- A DNS RR for specifying the location of services.
--
-- The target hostname field is not subject to
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4)
-- on output, but name compression is tolerated on input.  It canonicalises to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- Ordered canonically:
-- [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)
--
data T_srv = T_SRV
    { srvPriority :: Word16
    , srvWeight   :: Word16
    , srvPort     :: Word16
    , srvTarget   :: Domain -- not subject to name compression
    } deriving (Show)

-- | Equality is not case-senstive on the target host name.
instance Eq T_srv where
    a == b = (srvPriority a) ==              (srvPriority b)
          && (srvWeight   a) ==              (srvWeight   b)
          && (srvPort     a) ==              (srvPort     b)
          && (srvTarget   a) `equalWireHost` (srvTarget   b)

-- | Order is not case-senstive on the target host name.
instance Ord T_srv where
    a `compare` b = (srvPriority a) `compare`         (srvPriority b)
                 <> (srvWeight   a) `compare`         (srvWeight   b)
                 <> (srvPort     a) `compare`         (srvPort     b)
                 <> (srvTarget   a) `compareWireHost` (srvTarget   b)

instance Presentable T_srv where
    present T_SRV{..} =
        present srvPriority
        . presentSp srvWeight
        . presentSp srvPort
        . presentSp srvTarget

instance KnownRData T_srv where
    rdType _ = SRV
    {-# INLINE rdType #-}
    rdEncode T_SRV{..} = putSizedBuilder $
        mbWord16 srvPriority
        <> mbWord16 srvWeight
        <> mbWord16 srvPort
        -- No Name compression when encoding.
        <> mbWireForm srvTarget
    cnEncode rd@(T_SRV{srvTarget = t}) =
        rdEncode rd { srvTarget = canonicalise t }
    rdDecode _ _ = const do
        srvPriority <- get16
        srvWeight   <- get16
        srvPort     <- get16
        -- Name compression accepted when decoding.
        srvTarget   <- getDomain
        return $ RData $ T_SRV{..}

-- | [AFSDB RDATA](https://datatracker.ietf.org/doc/html/rfc1183#section-1).
-- see also [Use of AFSDB RRs](https://tools.ietf.org/html/rfc5864#section-5).
--
-- The hostname field is not subject to
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4)
-- on output, but SHOULD be accepted on input.
--
-- The hostname field canonicalises to lower case:
-- <https://datatracker.ietf.org/doc/html/rfc4034#section-6.2>
--
data T_afsdb = T_AFSDB
    { afsdbSubtype  :: Word16
    , afsdbHostname :: Domain
    } deriving (Show)

instance Eq T_afsdb where
    a == b = (afsdbSubtype  a) == (afsdbSubtype  b)
          && (afsdbHostname a) `equalWireHost` (afsdbHostname b)

instance Ord T_afsdb where
    a `compare` b = (afsdbSubtype  a) `compare`         (afsdbSubtype  b)
                 <> (afsdbHostname a) `compareWireHost` (afsdbHostname b)

instance Presentable T_afsdb where
    present T_AFSDB{..} =
        present afsdbSubtype
        . presentSp afsdbHostname

instance KnownRData T_afsdb where
    rdType _ = AFSDB
    {-# INLINE rdType #-}
    rdEncode T_AFSDB{..} = putSizedBuilder $
        mbWord16 afsdbSubtype
        -- No Name compression when encoding.
        <> mbWireForm afsdbHostname
    cnEncode T_AFSDB{..} =
        rdEncode $ T_AFSDB afsdbSubtype
                           (canonicalise afsdbHostname)
    rdDecode _ _ = const do
        afsdbSubtype  <- get16
        -- Name compression accepted when decoding.
        afsdbHostname <- getDomain
        return $ RData $ T_AFSDB{..}

-- | [NAPTR RDATA](https://www.rfc-editor.org/rfc/rfc3403.html#section-4)
-- Naming Authority Pointer.
--
-- >                                 1  1  1  1  1  1
-- >   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                     ORDER                     |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                   PREFERENCE                  |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                     FLAGS                     /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                   SERVICES                    /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                    REGEXP                     /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                  REPLACEMENT                  /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The /replacement/ domain field is not subject to
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4)
-- on output, but name compression is tolerated on input.  It canonicalises to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- The `Ord` instance is canonical.
--
data T_naptr = T_NAPTR
    { naptrOrder       :: Word16
    , naptrPreference  :: Word16
    , naptrFlags       :: ShortByteString
    , naptrServices    :: ShortByteString
    , naptrRegexp      :: ShortByteString
    , naptrReplacement :: Domain
    } deriving (Show)

-- | Equality is not case-senstive on the replacement domain.
instance Eq T_naptr where
    a == b = (naptrOrder       a) ==              (naptrOrder       b)
          && (naptrPreference  a) ==              (naptrPreference  b)
          && (naptrFlags       a) ==              (naptrFlags       b)
          && (naptrServices    a) ==              (naptrServices    b)
          && (naptrRegexp      a) ==              (naptrRegexp      b)
          && (naptrReplacement a) `equalWireHost` (naptrReplacement b)

-- | Order is not case-senstive on the replacement domain.
instance Ord T_naptr where
    a `compare` b = (naptrOrder       a) `compare`         (naptrOrder       b)
                 <> (naptrPreference  a) `compare`         (naptrPreference  b)
                 <> (naptrFlags       a) `strCompare`      (naptrFlags       b)
                 <> (naptrServices    a) `strCompare`      (naptrServices    b)
                 <> (naptrRegexp      a) `strCompare`      (naptrRegexp      b)
                 <> (naptrReplacement a) `compareWireHost` (naptrReplacement b)
      where
        strCompare = comparing DnsText

instance Presentable T_naptr where
    present T_NAPTR{..} =
        present     naptrOrder
        . presentSp naptrPreference
        . presentSp @DnsText (coerce naptrFlags)
        . presentSp @DnsText (coerce naptrServices)
        . presentSp @DnsText (coerce naptrRegexp)
        . presentSp naptrReplacement

instance KnownRData T_naptr where
    rdType _ = NAPTR
    {-# INLINE rdType #-}
    rdEncode T_NAPTR{..} = putSizedBuilder $
           mbWord16              naptrOrder
        <> mbWord16              naptrPreference
        <> mbShortByteStringLen8 naptrFlags
        <> mbShortByteStringLen8 naptrServices
        <> mbShortByteStringLen8 naptrRegexp
           -- no name compression
        <> mbWireForm            naptrReplacement
    cnEncode rd@(T_NAPTR{naptrReplacement = r}) =
        rdEncode rd { naptrReplacement = canonicalise r }
    rdDecode _ _ = const do
        naptrOrder       <- get16
        naptrPreference  <- get16
        naptrFlags       <- getShortByteStringLen8
        naptrServices    <- getShortByteStringLen8
        naptrRegexp      <- getShortByteStringLen8
           -- possible name decompression
        naptrReplacement <- getDomain
        return $ RData $ T_NAPTR{..}

-- | [AMTRELAY RDATA](https://datatracker.ietf.org/doc/html/rfc8777#section-4).
--
-- >   0                   1                   2                   3
-- >   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >  |   precedence  |D|    type     |                               |
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
-- >  ~                            relay                              ~
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- The @type@ field determines the format of the @relay@ field as follows:
--
--   - 0: empty
--   - 1: wire-form IPv4 address
--   - 2: wire-form IPv6 address
--   - 3: uncompressed wire-form domain name
--   - 4-127: reserved (unlikely to be specified)
--
-- Ordered canonically.
--
data T_amtrelay = T_AMTRELAY
    { amtPref  :: Word8 -- ^ Preference, lower is better
    , amtDisc  :: Bool  -- ^ Discovery optional
    , amtRelay :: AmtRelay
    } deriving (Eq, Ord, Show)

-- | New variants of the AmtRelay value type are not expected, so an ADT is
-- used to capture just the specified variants and an opaque catchall.
--
data AmtRelay = Amt_Nil
              | Amt_A IPv4
              | Amt_AAAA IPv6
              | Amt_Host Host
              | Amt_Any_ Word8 ShortByteString
  deriving (Eq, Ord, Show)

-- | /Smart constructor/ of opaque relay forms, that ensures a non-empty value
-- and type in [4,127].  The underlying @Amt_Any_@ constructor is not exposed.
--
pattern Amt_Opaque :: Word8 -> ShortByteString -> AmtRelay
pattern Amt_Opaque t b <- Amt_Any_ t b where
    Amt_Opaque t b | t > 3 && t < 128 && not (SB.null b) = Amt_Any_ t b
                   | otherwise = error "Invalid opaque AmtRelay"

amtTypeWord :: Bool -> Word8 -> Word8
amtTypeWord d t = bool t (0x80 .|. t) d

instance Presentable T_amtrelay where
    present T_AMTRELAY{..} = case amtRelay of
        Amt_Nil -> present amtPref
                   . presentSp (fromEnum amtDisc)
                   . presentSp @Word8 0
                   . presentSp "."
        Amt_A a -> present amtPref
                   . presentSp (fromEnum amtDisc)
                   . presentSp @Word8 1
                   . presentSp a
        Amt_AAAA a -> present amtPref
                      . presentSp (fromEnum amtDisc)
                      . presentSp @Word8 2
                      . presentSp a
        Amt_Host h -> present amtPref
                      . presentSp (fromEnum amtDisc)
                      . presentSp @Word8 3
                      . presentSp (fromHost h)
        Amt_Any_ t bs ->
            present "\\# "
            . present (2 + SB.length bs)
            . present ' '
            . (word8HexFixed amtPref <>)
            . (word8HexFixed (amtTypeWord amtDisc t) <>)
            . present @Bytes16 (coerce bs)

instance KnownRData T_amtrelay where
    rdType _ = AMTRELAY
    {-# INLINE rdType #-}
    rdEncode T_AMTRELAY{..} = do
        put8 amtPref
        case amtRelay of
            Amt_Nil -> put8 (amtTypeWord amtDisc 0)
            Amt_A a -> do
                put8 (amtTypeWord amtDisc 1)
                putIPv4 a
            Amt_AAAA a -> do
                put8 (amtTypeWord amtDisc 2)
                putIPv6 a
            Amt_Host h -> do
                put8 (amtTypeWord amtDisc 3)
                putWireForm (fromHost h)
            Amt_Any_ t bs -> do
                put8 (amtTypeWord amtDisc t)
                putShortByteString bs
    rdDecode _ _ len = do
        amtPref <- get8
        w <- get8
        let amtDisc = (w .&. 0x80) /= 0
            t = w .&. 0x7f
        amtRelay <- case t of
            0 -> pure Amt_Nil
            1 -> Amt_A <$> getIPv4
            2 -> Amt_AAAA <$> getIPv6
            3 -> Amt_Host . toHost <$> getDomain
            _ -> Amt_Any_ t <$> getShortNByteString (len - 2)
        pure $ RData $ T_AMTRELAY{..}
