{-|
Module      : Net.DNSBase.RData.Obsolete
Description : Obsolete RR types retained for wire-form parsing
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

A grab-bag of RR types that are no longer used in current zone
data but appear in historic records and zone-data archives.
They are defined here so wire-form parsers can read stray
examples without failing.  No new deployment should use any of
these types.

The module gathers four loose groups:

* Early host-name and mailbox pointers: 'T_md', 'T_mf', 'T_mb',
  'T_mg', 'T_mr' (the shared codec 'X_domain' is re-exported
  here).
* RFC 1035 and RFC 1183 records that never saw wide use:
  'T_minfo', 'T_x25', 'T_isdn', 'T_rt'.
* OSI / X.400-mapping records, all deprecated by RFC 9121:
  'T_nsap', 'T_nsapptr', 'T_px'.
* Other one-offs: 'T_gpos' (early geographic location,
  superseded by 'LOC'), 'T_kx' (Key Exchange), 'T_a6'
  (chained IPv6 addressing; obsoleted by RFC 6563).

'T_wks' (Well-Known Services) is re-exported here for
convenience; its definition lives in "Net.DNSBase.RData.WKS".

The pre-RFC-4034 records in this module lower-case their
embedded domains in canonical form; 'T_nsapptr' is the
exception (its derived instances compare the wire bytes
case-sensitively).
-}
{-# LANGUAGE RecordWildCards #-}

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

-- | The @MINFO@ resource record
-- ([RFC 1035 section 3.3.7](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.7))
-- — mailing-list request and owner addresses: two 'Domain'
-- fields, the request mailbox and the owner (bounce) mailbox.
--
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  /                    RMAILBX                    /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  /                    EMAILBX                    /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- Both fields are subject to wire-form name compression on encode
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- and canonicalise to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare both domain fields in
-- canonical wire form (via 'equalWireHost' / 'compareWireHost'),
-- so 'Ord' is canonical.
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

-- | The @X25@ resource record
-- ([RFC 1183 section 3.1](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.1))
-- — an X.25 PSDN address held as a single DNS
-- /character-string/.  RFC 1183 calls for at least four ASCII
-- digits, but the constructor does not enforce that — callers may
-- store any byte sequence that fits in a character-string (up to
-- 255 bytes).
--
-- The 'Ord' instance compares the payload as a DNS
-- character-string (length-prefixed lexicographic), so it agrees
-- with the canonical wire-form ordering of
-- [RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
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
    rdDecode _ _ = const $ RData . T_X25 <$> getShortByteStringLen8

-- | The @ISDN@ resource record
-- ([RFC 1183 section 3.2](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.2))
-- — the ISDN number of the owner host, with an optional
-- Direct-Dial-In subaddress.  Both fields are DNS
-- /character-strings/; only the address is mandatory.
--
-- The 'Ord' instance compares both fields as DNS
-- character-strings.  With the trailing DDI absent, the wire form
-- is shorter than any encoding with a present DDI, so 'Ord' agrees
-- with the canonical wire-form ordering of
-- [RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
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

-- | The @RT@ resource record
-- ([RFC 1183 section 3.3](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.3))
-- — Route-Through: a 16-bit preference and a 'Domain' naming an
-- intermediate host that will route packets to the owner.  Used
-- in the X.25 and ISDN era for hosts without their own wide-area
-- addresses.
--
-- The route-through domain is not subject to wire-form name
-- compression on encode but compression is tolerated on decode
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4)).
-- It canonicalises to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare the domain in canonical
-- wire form (via 'equalWireHost' / 'compareWireHost'), so 'Ord'
-- is canonical.
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

-- | The @NSAP@ resource record
-- ([RFC 1706 section 5](https://www.rfc-editor.org/rfc/rfc1706.html#section-5);
-- deprecated by [RFC 9121](https://www.rfc-editor.org/rfc/rfc9121))
-- — mapped a domain name to an OSI Network Service Access Point
-- address.  An opaque byte string carrying the NSAP value
-- verbatim; presented in zone-file syntax as a @0x@-prefixed hex
-- literal.
--
-- Derived 'Ord' compares the raw bytes, which matches the
-- canonical wire-form ordering of
-- [RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
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
    rdDecode _ _ = RData . T_NSAP <.> getShortNByteString

-- | The @NSAPPTR@ resource record
-- ([RFC 1348](https://www.rfc-editor.org/rfc/rfc1348#page-2);
-- obsoleted by @PTR@ in
-- [RFC 1706 section 6](https://www.rfc-editor.org/rfc/rfc1706.html#section-6),
-- deprecated by [RFC 9121](https://www.rfc-editor.org/rfc/rfc9121))
-- — the OSI counterpart of @PTR@, mapping an NSAP-derived owner
-- name to a domain name.
--
-- The target domain is not subject to wire-form name compression
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- and is /not/ in the
-- [RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)
-- list of types that lower-case their RDATA names.  Derived 'Eq'
-- and 'Ord' therefore compare the wire bytes verbatim
-- (case-sensitively).
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

-- | The @PX@ resource record
-- ([RFC 2163 section 4](https://www.rfc-editor.org/rfc/rfc2163.html#section-4);
-- deprecated by [RFC 9121](https://www.rfc-editor.org/rfc/rfc9121))
-- — points at X.400/RFC 822 mapping information: a 16-bit
-- preference and two 'Domain' fields naming the RFC 822 (SMTP)
-- and X.400 sides of the mapping.
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
-- Neither domain field is subject to wire-form name compression
-- on encode but compression is tolerated on decode
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4)).
-- Both canonicalise to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare both domains in canonical
-- wire form (via 'equalWireHost' / 'compareWireHost'), so 'Ord'
-- is canonical.
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

-- | The @GPOS@ resource record
-- ([RFC 1712 section 3](https://www.rfc-editor.org/rfc/rfc1712.html#section-3))
-- — an early geographical-location record: longitude, latitude,
-- and altitude as three DNS /character-strings/ holding decimal
-- floating-point text.  Superseded by @LOC@-style records and not
-- used in modern zone data.
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                 LONGITUDE                  /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                  LATITUDE                  /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                  ALTITUDE                  /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The 'Ord' instance compares the three fields as DNS
-- character-strings, agreeing with the canonical wire-form
-- ordering of
-- [RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
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

-- | The @KX@ resource record
-- ([RFC 2230 section 3.1](https://www.rfc-editor.org/rfc/rfc2230.html#section-3.1))
-- — names a Key Exchange host for the owner: a 16-bit preference
-- and a 'Domain' naming the exchanger.  Defined for the DNSSEC
-- precursor work; never widely deployed.
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                  PREFERENCE                   |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                   EXCHANGER                   /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The exchanger field is not subject to wire-form name compression
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- and canonicalises to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare the exchanger in canonical
-- wire form (via 'equalWireHost' / 'compareWireHost'), so 'Ord'
-- is canonical.
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

-- | The @A6@ resource record
-- ([RFC 2874 section 3.1](https://www.rfc-editor.org/rfc/rfc2874.html#section-3.1);
-- obsoleted by [RFC 6563](https://www.rfc-editor.org/rfc/rfc6563.html))
-- — an experimental chained IPv6 addressing scheme.  Each record
-- carries a prefix length, an address suffix containing the
-- low-order bits, and a 'Domain' naming where to look up the
-- remaining prefix bits.  Resolution walked the chain to assemble
-- the full address.  The deployment experience reported in RFC
-- 6563 led to A6 being abandoned in favour of plain 'Net.DNSBase.RData.A.T_aaaa'
-- records.
--
-- > +-----------+------------------+-------------------+
-- > |Prefix len.|  Address suffix  |    Prefix name    |
-- > | (1 octet) |  (0..16 octets)  |  (0..255 octets)  |
-- > +-----------+------------------+-------------------+
--
-- The wire encoding rules are:
--
-- * The prefix length is an unsigned octet between 0 and 128.
-- * The address-suffix field carries exactly enough octets to
--   hold @128 - /prefix-length/@ bits, with up to seven leading
--   pad bits set to zero so the field is an integral number of
--   bytes.
-- * The prefix-name field is a wire-form 'Domain'.  It is absent
--   when the prefix length is zero (the suffix already holds the
--   whole address); the suffix field is absent when the prefix
--   length is 128 (the whole address comes from the chain).
-- * The prefix-name is not subject to wire-form name compression
--   ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
--   and canonicalises to lower case
--   ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
--
-- The 'Eq' and 'Ord' instances compare the prefix-name field in
-- canonical wire form (via 'toHost'), so 'Ord' is canonical.
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
