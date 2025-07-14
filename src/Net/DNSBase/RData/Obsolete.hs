{-# LANGUAGE
    CPP
  , RecordWildCards
  #-}
module Net.DNSBase.RData.Obsolete
    ( -- * Obsolete RR types
      -- ** Obsolete RR types representing a host name or mailbox.
      X_domain(T_MD, T_MF, T_MB, T_MG, T_MR)
    , T_md
    , T_mf
    , T_mb
    , T_mg
    , T_mr
      -- ** Other obsolete RR types.
    , T_wks(..)
    , WksProto(..)
    , T_minfo(..)
    , T_x25(..)
    , T_isdn(..)
    , T_rt(..)
    , T_nsap(..)
    , T_nsapptr(..)
    , T_px(..)
    , T_gpos(..)
    , T_kx(..)
    , T_a6(T_A6)
    ) where

import qualified Data.ByteString.Short as SB
import Net.DNSBase.Internal.Util
import Net.DNSBase.RData.Internal.XNAME

import Net.DNSBase.Bytes
import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RData.WKS
import Net.DNSBase.RRTYPE
import Net.DNSBase.Text

-- | [MINFO RDATA](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.7).
-- Mailing list request and owner addresses.
--
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  /                    RMAILBX                    /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  /                    EMAILBX                    /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- Both fields are subject to name compression:
-- <https://datatracker.ietf.org/doc/html/rfc3597#section-4>
-- and canonicalise to lower case:
-- <https://datatracker.ietf.org/doc/html/rfc4034#section-6.2>.
--
-- - The `Ord` and `Eq` instances are are case-insensitive.
-- - The `Ord` instance is canonical.
--
data T_minfo = T_MINFO
    { minfoRmailbx :: Domain -- ^ Request address
    , minfoEmailbx :: Domain -- ^ Owner (bounce) address
    } deriving (Show)

-- | Case-insensitive wire-form equality.
instance Eq T_minfo where
    a == b = (minfoRmailbx a) `equalWireHost` (minfoRmailbx b)
          && (minfoEmailbx a) `equalWireHost` (minfoEmailbx b)

-- | Case-insensitive wire-form order.
instance Ord T_minfo where
    a `compare` b = (minfoRmailbx a) `compareWireHost` (minfoRmailbx b)
                 <> (minfoEmailbx a) `compareWireHost` (minfoEmailbx b)

instance Presentable T_minfo where
    present T_MINFO{..} =
        present minfoRmailbx
        . presentSp minfoEmailbx

instance KnownRData T_minfo where
    rdType _ = MINFO
    {-# INLINE rdType #-}
    rdEncode T_MINFO{..} = do
        -- Subject to name compression.
        putDomain minfoRmailbx
        putDomain minfoEmailbx
    cnEncode T_MINFO{..} = putSizedBuilder $
           mbWireForm (canonicalise minfoRmailbx)
        <> mbWireForm (canonicalise minfoEmailbx)
    rdDecode _ _ = const do
        -- Subject to name compression.
        minfoRmailbx <- getDomain
        minfoEmailbx <- getDomain
        return $ RData $ T_MINFO{..}

-- | [X25 RDATA](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.1).
-- X.25 PSDN address (phone number).  Syntactically a /character-string/.
--
-- - Should consist of just digits and be at least four digits long, but this
--   is not enforced here.
--
newtype T_x25 = T_X25 SB.ShortByteString
    deriving (Eq, Show)

instance Ord T_x25 where
    (T_X25 a) `compare` (T_X25 b) = comparing DnsText a b

instance Presentable T_x25 where
    present (T_X25 str) = present @DnsText (coerce str)

instance KnownRData T_x25 where
    rdType _ = X25
    {-# INLINE rdType #-}
    rdEncode = putShortByteStringLen8 . coerce
    rdDecode _ _ = const do
        RData . T_X25 <$> getShortByteStringLen8

-- | [ISDN RDATA](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.2).
-- <ISDN-address> identifies the ISDN number of <owner> and DDI (Direct
-- Dial In) if any.
--
data T_isdn = T_ISDN SB.ShortByteString (Maybe SB.ShortByteString)
    deriving (Eq, Show)

instance Ord T_isdn where
    (T_ISDN aa ad) `compare` (T_ISDN ba bd) = aa `strCompare`  ba
                                           <> ad `mstrCompare` bd
      where
        strCompare = comparing DnsText
        mstrCompare = comparing (fmap DnsText)

instance Presentable T_isdn where
    present (T_ISDN address ddi) =
        present @DnsText (coerce address)
        . maybe id (presentSp @DnsText . coerce) ddi

instance KnownRData T_isdn where
    rdType _ = ISDN
    {-# INLINE rdType #-}
    rdEncode (T_ISDN address ddi) = do
        putShortByteStringLen8 address
        mapM_ putShortByteStringLen8 ddi
    rdDecode _ _ len = do
        pos0 <- getPosition
        address <- getShortByteStringLen8
        used <- subtract pos0 <$> getPosition
        ddi <- if | used == len -> pure Nothing
                  | otherwise   -> Just <$> getShortByteStringLen8
        pure $ RData $ T_ISDN address ddi

-- | [RT RDATA](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.2).
-- The RT (Route Through) resource record provides a route-through binding for
-- hosts that do not have their own direct wide area network addresses.
--
-- - Equality and order are case-insensitive.
-- - The `Ord` instance is canonical.
--
-- Name compression is not used on output, but supported on input, in
-- accordance with
-- [RFC3597](https://datatracker.ietf.org/doc/html/rfc3597#section-4).
--
-- The route through domain canonicalises to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
data T_rt = T_RT Word16 Domain
    deriving (Show)

instance Eq T_rt where
    (T_RT pa ra) == (T_RT pb rb) = pa == pb && ra `equalWireHost` rb

instance Ord T_rt where
    (T_RT pa ra) `compare` (T_RT pb rb) =
        pa `compare` pb
     <> ra `compareWireHost` rb

instance Presentable T_rt where
    present (T_RT pref router) = present pref . presentSp router

instance KnownRData T_rt where
    rdType _ = RT
    {-# INLINE rdType #-}
    rdEncode (T_RT pref router) = putSizedBuilder $
        mbWord16 pref <> mbWireForm router
    cnEncode (T_RT pref router) =
        rdEncode $ T_RT pref (canonicalise router)
    rdDecode _ _ = const do
        pref <- get16
        router <- getDomain
        pure $ RData $ T_RT pref router

-- | [NSAP RDATA](https://www.rfc-editor.org/rfc/rfc1706.html#section-5)
-- [DEPRECATED](https://www.rfc-editor.org/rfc/rfc9121)
-- The @NSAP@ RR was used to map from domain names to NSAPs.
--
-- The `Ord` instance is canonical.
--
newtype T_nsap = T_NSAP SB.ShortByteString
    deriving (Eq, Ord)

instance Show T_nsap where
    showsPrec p a = showString "0x" . showsPrec @Bytes16 p (coerce a)

instance Presentable T_nsap where
    present a = present @String "0x" . present @Bytes16 (coerce a)

instance KnownRData T_nsap where
    rdType _ = NSAP
    {-# INLINE rdType #-}
    rdEncode = putSizedBuilder . mbShortByteString . coerce
    rdDecode _ _ len = RData . T_NSAP <$> getShortNByteString len

-- | [NSAPPTR RDATA](https://www.rfc-editor.org/rfc/rfc1348#page-2)
-- [Obsoleted by PTR](https://www.rfc-editor.org/rfc/rfc1706.html#section-6)
-- [DEPRECATED](https://www.rfc-editor.org/rfc/rfc9121)
--
-- Not subject to either
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4)
-- [canonicalisation](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- Equality and comparison are case-sensitive.
--
newtype T_nsapptr = T_NSAPPTR Domain -- ^ Target 'Domain'
    deriving (Eq, Ord, Show)

instance Presentable T_nsapptr where
    present = present @Domain . coerce

instance KnownRData T_nsapptr where
    rdType _ = NSAPPTR
    {-# INLINE rdType #-}
    rdEncode = putSizedBuilder . mbWireForm . coerce
    rdDecode _ _ = const do
        RData . T_NSAPPTR <$> getDomainNC

-- | [PX RDATA](https://www.rfc-editor.org/rfc/rfc1348#page-2)
-- Pointer to X.400/RFC822 mapping information.
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                  PREFERENCE                   |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                    MAP822                     /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                    MAPX400                    /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The domain elements are subject to name compression only when decoding:
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4),
-- and canonicalise to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- Equality and comparison are case-insensitive.
--
data T_px = T_PX
    { pxPref    :: Word16
    , pxMap822  :: Domain
    , pxMapX400 :: Domain
    } deriving (Show)

instance Eq T_px where
    a == b = pxPref    a ==              pxPref    b
          && pxMap822  a `equalWireHost` pxMap822  b
          && pxMapX400 a `equalWireHost` pxMapX400 b

instance Ord T_px where
    a `compare` b = pxPref    a `compare`         pxPref    b
                 <> pxMap822  a `compareWireHost` pxMap822  b
                 <> pxMapX400 a `compareWireHost` pxMapX400 b

instance Presentable T_px where
    present T_PX{..} =
        present pxPref
        . presentSp pxMap822
        . presentSp pxMapX400

instance KnownRData T_px where
    rdType _ = PX
    {-# INLINE rdType #-}
    rdEncode T_PX{..} = putSizedBuilder $
        mbWord16 pxPref
        <> mbWireForm pxMap822
        <> mbWireForm pxMapX400
    cnEncode T_PX{..} =
        rdEncode $ T_PX pxPref
                        (canonicalise pxMap822)
                        (canonicalise pxMapX400)
    rdDecode _ _ = const do
        pxPref    <- get16
        pxMap822  <- getDomain
        pxMapX400 <- getDomain
        pure $ RData T_PX{..}

-- | [GPOS RDATA](https://www.rfc-editor.org/rfc/rfc1712.html#section-3).
-- Geographical location as three character strings, representing floating
-- point numbers.
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                 LONGITUDE                  /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                  LATITUDE                  /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                  ALTITUDE                  /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
data T_gpos = T_GPOS
    { gposLongitude :: SB.ShortByteString
    , gposLatitude  :: SB.ShortByteString
    , gposAltitude  :: SB.ShortByteString
    } deriving (Eq, Show)

instance Ord T_gpos where
    a `compare` b = gposLongitude a `strCompare` gposLongitude b
                 <> gposLatitude  a `strCompare` gposLatitude  b
                 <> gposAltitude  a `strCompare` gposAltitude  b
      where
        strCompare = comparing DnsText

instance Presentable T_gpos where
    present T_GPOS{..} =
        present     @DnsText (coerce gposLongitude)
        . presentSp @DnsText (coerce gposLatitude)
        . presentSp @DnsText (coerce gposAltitude)

instance KnownRData T_gpos where
    rdType _ = GPOS
    {-# INLINE rdType #-}
    rdEncode T_GPOS{..} = putSizedBuilder $
        mbShortByteStringLen8    gposLongitude
        <> mbShortByteStringLen8 gposLatitude
        <> mbShortByteStringLen8 gposAltitude
    rdDecode _ _ = const do
        gposLongitude <- getShortByteStringLen8
        gposLatitude  <- getShortByteStringLen8
        gposAltitude  <- getShortByteStringLen8
        pure $ RData T_GPOS{..}

-- | [KX RDATA](https://www.rfc-editor.org/rfc/rfc2230.html#section-3.1).
-- Key Exchange host.
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                  PREFERENCE                   |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                   EXCHANGER                   /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The domain name is not subject to name compression:
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4),
-- but canonicalise to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- Equality and comparison are case-insensitive.
--
data T_kx = T_KX
    { kxPref :: Word16
    , kxExch :: Domain
    } deriving (Show)

instance Eq T_kx where
    a == b = kxPref a ==              kxPref b
          && kxExch a `equalWireHost` kxExch b

instance Ord T_kx where
    a `compare` b = kxPref a `compare`         kxPref b
                 <> kxExch a `compareWireHost` kxExch b

instance Presentable T_kx where
    present T_KX{..} = present kxPref . presentSp kxExch

instance KnownRData T_kx where
    rdType _ = KX
    {-# INLINE rdType #-}

    rdEncode T_KX{..} = putSizedBuilder $
        mbWord16 kxPref
        <> mbWireForm kxExch
    cnEncode rd@(T_KX{kxExch = d}) =
        rdEncode rd {kxExch = canonicalise d}
    rdDecode _ _ = const do
        kxPref <- get16
        kxExch <- getDomainNC
        pure $ RData T_KX{..}

-- | [A6 RDATA](https://www.rfc-editor.org/rfc/rfc2874.html#section-3.1),
-- [Obsolete](https://www.rfc-editor.org/rfc/rfc6563.html).
-- Renumberable and aggregatable IPv6 addressing
--
-- > +-----------+------------------+-------------------+
-- > |Prefix len.|  Address suffix  |    Prefix name    |
-- > | (1 octet) |  (0..16 octets)  |  (0..255 octets)  |
-- > +-----------+------------------+-------------------+
--
-- o  A prefix length, encoded as an eight-bit unsigned integer with
--    value between 0 and 128 inclusive.
--
-- o  An IPv6 address suffix, encoded in network order (high-order octet
--    first).  There MUST be exactly enough octets in this field to
--    contain a number of bits equal to 128 minus prefix length, with 0
--    to 7 leading pad bits to make this field an integral number of
--    octets.  Pad bits, if present, MUST be set to zero when loading a
--    zone file and ignored (other than for SIG [DNSSEC] verification)
--    on reception.
--
-- o  The name of the prefix, encoded as a domain name.  By the rules of
--    [DNSIS], this name MUST NOT be compressed.
--
-- The domain name component SHALL NOT be present if the prefix length
-- is zero.  The address suffix component SHALL NOT be present if the
-- prefix length is 128.
--
-- The domain name is not subject to
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4),
-- but canonicalise to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- Equality and comparison are case-insensitive.
--
data T_a6 = T_a6
    { a6Prefix :: Word8
    , a6Suffix :: IPv6
    , a6Domain :: Maybe Domain
    } deriving (Show)

instance Eq T_a6 where
    a == b = (           a6Prefix a) == (           a6Prefix b)
          && (           a6Suffix a) == (           a6Suffix b)
          && (toHost <$> a6Domain a) == (toHost <$> a6Domain b)

instance Ord T_a6 where
    a `compare` b = (           a6Prefix a) `compare` (           a6Prefix b)
                 <> (           a6Suffix a) `compare` (           a6Suffix b)
                 <> (toHost <$> a6Domain a) `compare` (toHost <$> a6Domain b)

-- | /Smart constructor/ for @A6@ records:
--
-- - Silently caps the prefix length to 128
-- - Ignores the domain when the prefix length is 0
-- - Otherwise, uses the root domain if no domain is provided
--
pattern T_A6 :: Word8 -> IPv6 -> Maybe Domain -> T_a6
pattern T_A6 prefix suffix domain <- T_a6 prefix suffix domain where
    T_A6 prefix suffix domain = T_a6{..}
      where
        a6Prefix = bool 128 prefix (prefix <= 128)
        a6Domain | prefix == 0 = Nothing
                 | otherwise   = Just $! fromMaybe RootDomain domain
        a6Suffix | (s0, s1, s2, s3) <- fromIPv6w suffix
                   = toIPv6w (s0 .&. m0, s1 .&. m1, s2 .&. m2, s3 .&. m3)
          where
            (m0, m1, m2, m3) = mask128 $ fromIntegral a6Prefix

instance Presentable T_a6 where
    present T_a6{..} =
        present a6Prefix
        . presentSp a6Suffix
        . maybe id presentSp a6Domain

instance KnownRData T_a6 where
    rdType _ = A6
    {-# INLINE rdType #-}

    rdEncode T_a6{..} = putSizedBuilder $
        mbWord8 a6Prefix
        <> mconcat [mbWord8 (fromIntegral w) | w <- bytesFromIPv6]
        <> maybe mempty mbWireForm a6Domain
      where
        npad = fromIntegral a6Prefix `shiftR` 3
        bytesFromIPv6 = drop npad $ fromIPv6b a6Suffix

    cnEncode rd@(T_a6{a6Domain = Just d}) =
        rdEncode rd {a6Domain = Just (canonicalise d)}
    cnEncode rd = rdEncode rd

    rdDecode _ _ = const do
        a6Prefix <- get8
        when (a6Prefix > 128) do
            failSGet "A6 prefix exceeds 128"
        let npad = fromIntegral a6Prefix `shiftR` 3
        a6Suffix <- bytesToIPv6 npad <$> getNBytes (16 - npad)
        a6Domain <- if | a6Prefix == 0 -> pure Nothing
                       | otherwise     -> Just <$> getDomainNC
        pure $ RData T_a6{..}
      where
        bytesToIPv6 npad = toIPv6b . (replicate npad 0 ++) . map fromIntegral

--------------------

-- | Mask upper @p@ bits of IPv6 address.
mask128 :: Int -> (Word32, Word32, Word32, Word32)
mask128 p | p < 64    = (w0, w1, m32, m32)
          | otherwise = (0,   0,  w2,  w3)
  where
    m64 = 0xffff_ffff_ffff_ffff :: Word64
    m32 = 0xffff_ffff :: Word32
    hi = m64 `shiftR` p
    lo = m64 `shiftR` (p - 64)
    w0 = fromIntegral @Word64 @Word32 (hi `shiftR` 32)
    w1 = fromIntegral @Word64 @Word32 hi
    w2 = fromIntegral @Word64 @Word32 (lo `shiftR` 32)
    w3 = fromIntegral @Word64 @Word32 lo
