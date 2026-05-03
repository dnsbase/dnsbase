{-|
Module      : Net.DNSBase.RData.SRV
Description : Service-endpoint and locator records (MX, SRV, AFSDB, NAPTR, NID/L32/L64/LP, AMTRELAY)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

This module gathers RR types that map a name to a service
endpoint or address locator.  'T_mx' (RFC 1035), 'T_srv'
(RFC 2782), 'T_afsdb' (RFC 1183), and 'T_naptr' (RFC 3403) are
pre-RFC-4034 records pointing at a host via a domain name;
canonical RDATA lower-cases the embedded domain.  The ILNP
family ('T_nid', 'T_l32', 'T_l64', 'T_lp'; RFC 6742) and
'T_amtrelay' (RFC 8777) are later records — those with a
domain field treat it case-sensitively in canonical form per
RFC 6840 section 5.1.
-}
{-# LANGUAGE
    MagicHash
  , RecordWildCards
  , UndecidableInstances
  #-}

module Net.DNSBase.RData.SRV
    ( T_mx(..)
    , T_srv(..)
    , T_afsdb(..)
    , T_naptr(..)
      -- * NID and L64
    , X_nid(.., T_NID, T_L64)
    , type XnidConName, T_nid, T_l64
      -- *** 'T_NID' fields
    , nidPref
    , nidAddr
      -- *** 'T_L64' fields
    , l64Pref
    , l64Addr
      -- * L32
    , T_l32(..)
      -- * LP
    , T_lp(..)
      -- * AMTRELAY
    , T_amtrelay(..)
    , AmtRelay(Amt_Nil, Amt_A, Amt_AAAA, Amt_Host, Amt_Opaque)
    ) where

import qualified Data.ByteString.Short as SB
import Data.ByteString.Builder (char8, word8HexFixed, word16HexFixed)
import GHC.Exts (proxy#)
import GHC.TypeLits as TL (TypeError, ErrorMessage(..))
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal')

import Net.DNSBase.Internal.Util
import Net.DNSBase.Internal.Bytes

import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Nat16
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE
import Net.DNSBase.Text

type XnidConName :: Nat -> Symbol
type family XnidConName n where
    XnidConName N_nid = "T_NID"
    XnidConName N_l64 = "T_L64"
    XnidConName n     = TypeError
                        ( ShowType n
                          :<>: TL.Text " is not a NID or L64 RRTYPE" )

-- | X_nid specialised to @NID@ records.
type T_nid = X_nid N_nid
-- | X_nid specialised to @L64@ records.
type T_l64 = X_nid N_l64

-- | Record pattern synonym viewing the shared 'X_nid' record as an
-- @NID@ (Node Identifier) record, RFC 6742.  Fields: 'nidPref',
-- 'nidAddr'.  Not coercible to/from 'T_l64': the role of 'X_nid' is
-- /nominal/ because the 64-bit payload means a Node-ID here and a
-- 64-bit locator prefix in L64.
pattern T_NID :: Word16 -- ^ Preference
              -> Word64 -- ^ Node Identifier
              -> T_nid
pattern T_NID { nidPref, nidAddr } = (X_NID nidPref nidAddr :: T_nid)
{-# COMPLETE T_NID #-}

-- | Record pattern synonym viewing the shared 'X_nid' record as an
-- @L64@ (64-bit locator) record, RFC 6742.  Fields: 'l64Pref',
-- 'l64Addr'.  Not coercible to/from 'T_nid' (see 'T_NID' note).
pattern T_L64 :: Word16 -- ^ Preference
              -> Word64 -- ^ 64-bit locator prefix
              -> T_l64
pattern T_L64 { l64Pref, l64Addr } = (X_NID l64Pref l64Addr :: T_l64)
{-# COMPLETE T_L64 #-}

-- | The @MX@ resource record
-- ([RFC 1035 section 3.3.9](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.9))
-- — a mail exchanger for the owner name: a 16-bit preference
-- (lower is preferred) and a 'Domain' naming the exchange host.
--
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  |                  PREFERENCE                   |
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  /                   EXCHANGE                    /
-- >  /                                               /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The exchange field is subject to wire-form name compression on
-- encode
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- and canonicalises to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare the exchange in canonical
-- wire form (via 'equalWireHost' / 'compareWireHost'), so 'Ord'
-- is canonical.
--
-- A name that resolves to a CNAME should not be used in the
-- exchange field
-- ([RFC 2181 section 10.3](https://datatracker.ietf.org/doc/html/rfc2181#section-10.3),
-- [RFC 5321 section 5.1](https://datatracker.ietf.org/doc/html/rfc5321#section-5.1)).
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

-- | The @SRV@ resource record
-- ([RFC 2782](https://datatracker.ietf.org/doc/html/rfc2782))
-- — names the location of a service: 16-bit priority, weight,
-- and port, plus a 'Domain' naming the target host.
--
-- The target field is not subject to wire-form name compression
-- on encode
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- but compression is tolerated on decode.  It canonicalises to
-- lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare the target in canonical
-- wire form (via 'equalWireHost' / 'compareWireHost'), so 'Ord'
-- is canonical.
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

-- | The @AFSDB@ resource record
-- ([RFC 1183 section 1](https://datatracker.ietf.org/doc/html/rfc1183#section-1);
-- see also
-- [RFC 5864 section 5](https://tools.ietf.org/html/rfc5864#section-5))
-- — points at an AFS-cell or DCE-authentication-cell server:
-- a 16-bit subtype tag and a 'Domain' hostname.
--
-- The hostname field is not subject to wire-form name compression
-- on encode but compression is tolerated on decode.  It
-- canonicalises to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare the hostname in canonical
-- wire form (via 'equalWireHost' / 'compareWireHost'), so 'Ord'
-- is canonical.
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

-- | The @NAPTR@ resource record
-- ([RFC 3403 section 4](https://www.rfc-editor.org/rfc/rfc3403.html#section-4))
-- — Naming Authority Pointer: a rewriting rule that translates
-- the owner name into another resource via the flags/services
-- tags, an optional regexp, and a replacement domain.
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
-- The replacement field is not subject to wire-form name
-- compression on encode but compression is tolerated on decode.
-- It canonicalises to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare the replacement in
-- canonical wire form (via 'equalWireHost' / 'compareWireHost')
-- and the character-string fields as DNS character-strings, so
-- 'Ord' is canonical.
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

-- | Shared wire-format representation for ILNP node-identifier
-- and locator records: @NID@
-- ([RFC 6742 section 2.1.1](https://www.rfc-editor.org/rfc/rfc6742.html#section-2.1.1))
-- carries a 64-bit Node-ID, and @L64@
-- ([RFC 6742 section 2.3.1](https://www.rfc-editor.org/rfc/rfc6742.html#section-2.3.1))
-- carries a 64-bit IPv6 locator prefix.  The type parameter @n@
-- (either 'N_nid' or 'N_l64') determines the RR type.  Each has
-- its own type synonym ('T_nid', 'T_l64') and matching record
-- pattern synonym ('T_NID', 'T_L64') with the corresponding
-- field-name prefix (@nid@, @l64@).  The role of 'X_nid' is
-- /nominal/: the 64-bit payload means different things in each,
-- so 'T_nid' and 'T_l64' are not coercible.
--
-- Derived 'Ord' is canonical: no embedded domain, fields compared
-- in wire-encoding order.  See 'T_l32' and 'T_lp' for the rest
-- of the ILNP record family.
--
-- >   0                   1                   2                   3
-- >   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >  |          Preference           |                               |
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
-- >  |                             NodeID                            |
-- >  +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >  |                               |
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
type X_nid :: Nat -> Type
type role X_nid nominal
data X_nid n = X_NID
    { _nidPref :: Word16 -- ^ Preference
    , _nidAddr :: Word64 -- ^ Node ID or 64-bit IPv6 prefix
    }
deriving instance (KnownSymbol (XnidConName n)) => Eq (X_nid n)
deriving instance (KnownSymbol (XnidConName n)) => Ord (X_nid n)

instance (Nat16 n, KnownSymbol (XnidConName n)) => Show (X_nid n) where
    showsPrec p X_NID{..} = showsP p $
        showString (symbolVal' (proxy# @(XnidConName n)))
        . showChar ' ' . shows' _nidPref
        . showChar ' ' . shows' _nidAddr

instance (KnownSymbol (XnidConName n)) => Presentable (X_nid n) where
    present X_NID{..} =
        present _nidPref
        . \k -> bld ' ' 48 <> bld ':' 32 <> bld ':' 16 <> bld ':'  0 <> k
      where
        bld :: Char -> Int -> Builder
        bld sep shft = char8 sep <>
            (word16HexFixed $ fromIntegral $ _nidAddr `shiftR` shft)

instance (Nat16 n, KnownSymbol (XnidConName n)) => KnownRData (X_nid n) where
    rdType _ = RRTYPE $ natToWord16 n
    {-# INLINE rdType #-}
    rdEncode X_NID{..} = putSizedBuilder $
           mbWord16              _nidPref
        <> mbWord64              _nidAddr
    rdDecode _ _ = const do
        _nidPref          <- get16
        _nidAddr          <- get64
        pure $ RData (X_NID{..} :: X_nid n)

-- | The @L32@ resource record
-- ([RFC 6742 section 2.2.1](https://www.rfc-editor.org/rfc/rfc6742.html#section-2.2.1))
-- — an ILNP 32-bit locator: a 16-bit preference and a 32-bit
-- network locator carried in an 'IPv4' value.
--
-- >  0                   1                   2                   3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |          Preference           |      Locator32 (16 MSBs)      |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |     Locator32 (16 LSBs)       |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- Derived 'Ord' is canonical: no embedded domain, fields compared
-- in wire-encoding order.  See 'X_nid' and 'T_lp' for the rest
-- of the ILNP record family.
data T_l32 = T_L32
    { l32Pref :: Word16
    , l32Addr :: IPv4
    } deriving (Eq, Ord, Show)

instance Presentable T_l32 where
    present T_L32{..} = present l32Pref . presentSp l32Addr

instance KnownRData T_l32 where
    rdType _ = L32
    {-# INLINE rdType #-}
    rdEncode T_L32{..} = putSizedBuilder $
           mbWord16              l32Pref
        <> mbWord32              (fromIPv4w l32Addr)
    rdDecode _ _ = const do
        l32Pref          <- get16
        l32Addr          <- toIPv4w <$> get32
        pure $ RData $ T_L32{..}


-- | The @LP@ resource record
-- ([RFC 6742 section 2.4.1](https://www.rfc-editor.org/rfc/rfc6742.html#section-2.4.1))
-- — an ILNP locator pointer: a 16-bit preference and a 'Domain'
-- naming a host that publishes locator records.
--
-- >  0                   1                   2                   3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |          Preference           |                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
-- > /                                                               /
-- > /                              FQDN                             /
-- > /                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- The FQDN field is not subject to wire-form name compression.
-- The 'Eq' and 'Ord' instances compare the FQDN case-insensitively
-- in wire form (via 'equalWireHost' / 'compareWireHost').
--
-- See 'X_nid' and 'T_l32' for the rest of the ILNP record family.
data T_lp = T_LP
    { lpPref :: Word16
    , lpFqdn :: Domain
    } deriving (Show)

-- | Case-insensitive wire-form equality.
instance Eq T_lp where
    a == b = (lpPref a) ==              (lpPref b)
          && (lpFqdn a) `equalWireHost` (lpFqdn b)

-- | Case-insensitive wire-form order.
instance Ord T_lp where
    compare a b = (lpPref a) `compare`         (lpPref b)
               <> (lpFqdn a) `compareWireHost` (lpFqdn b)

instance Presentable T_lp where
    present T_LP{..} = present lpPref . presentSp lpFqdn

instance KnownRData T_lp where
    rdType _ = LP
    {-# INLINE rdType #-}
    rdEncode T_LP{..} = putSizedBuilder $
        mbWord16 lpPref
        <> mbWireForm lpFqdn
    rdDecode _ _ = const do
        lpPref <- get16
        lpFqdn <- getDomainNC
        pure $ RData $ T_LP{..}

-- | The @AMTRELAY@ resource record
-- ([RFC 8777 section 4](https://datatracker.ietf.org/doc/html/rfc8777#section-4))
-- — the relay-address for AMT (Automatic Multicast Tunneling)
-- discovery.  An 8-bit /precedence/, a 1-bit /discovery-optional/
-- flag, a 7-bit relay-type field, and an 'AmtRelay' value whose
-- format depends on the type:
--
-- > 0       empty
-- > 1       wire-form IPv4 address
-- > 2       wire-form IPv6 address
-- > 3       uncompressed wire-form domain name
-- > 4-127   reserved (unlikely to be specified)
--
-- >   0                   1                   2                   3
-- >   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >  |   precedence  |D|    type     |                               |
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
-- >  ~                            relay                              ~
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- Derived 'Ord' compares precedence, then discovery flag, then
-- 'AmtRelay' (constructor order, then field), matching the
-- canonical wire-form ordering.  The 'Domain' inside an
-- @Amt_Host@ relay is compared case-sensitively, as is the
-- convention for RR types defined after RFC 4034.
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
    rdDecode _ _ = const do
        amtPref <- get8
        w <- get8
        let amtDisc = (w .&. 0x80) /= 0
            t = w .&. 0x7f
        amtRelay <- case t of
            0 -> pure Amt_Nil
            1 -> Amt_A <$> getIPv4
            2 -> Amt_AAAA <$> getIPv6
            3 -> Amt_Host . toHost <$> getDomain
            _ -> Amt_Any_ t <$> getShortByteString
        pure $ RData $ T_AMTRELAY{..}
