{-# LANGUAGE
    RecordWildCards
  , UndecidableInstances
  #-}
module Net.DNSBase.RData.Dnssec
    ( -- * DS and DNSKEY
      -- ** DS resource records
      X_ds(.., T_DS, T_CDS), T_ds, T_cds
      -- ** DNSKEY resource records
    , X_key(.., T_KEY, T_DNSKEY, T_CDNSKEY), T_key, T_dnskey, T_cdnskey
    , keytag
      -- * RRSIGs
    , X_sig(.., T_SIG, T_RRSIG), T_sig, T_rrsig
      -- * Zone digest
    , T_zonemd(..)
    , module Net.DNSBase.RData.NSEC
    ) where

import qualified Data.ByteString.Short as SB
import Data.Foldable (foldl')
import GHC.TypeLits (TypeError, ErrorMessage(..))
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal)

import Net.DNSBase.Internal.Util

import Net.DNSBase.Bytes
import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Nat16
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RData.NSEC
import Net.DNSBase.RRTYPE
import Net.DNSBase.Secalgs

type XdsConName :: Nat -> Symbol
type family XdsConName n where
    XdsConName N_ds  = "T_DS"
    XdsConName N_cds = "T_CDS"
    XdsConName n     = TypeError
                     ( ShowType n
                       :<>: Text " is not a DS or CDS RRTYPE" )

type XkeyConName :: Nat -> Symbol
type family XkeyConName n where
    XkeyConName N_dnskey  = "T_DNSKEY"
    XkeyConName N_cdnskey = "T_CDNSKEY"
    XkeyConName N_key     = "T_KEY"
    XkeyConName n         = TypeError
                            ( ShowType n
                              :<>: Text " is not a DNSSEC key RRTYPE" )

type XsigConName :: Nat -> Symbol
type family XsigConName n where
    XsigConName N_rrsig  = "T_RRSIG"
    XsigConName N_sig    = "T_SIG"
    XsigConName n        = TypeError
                           ( ShowType n
                             :<>: Text " is not a SIG or RRSIG RRTYPE" )

-- | @DS@ and @CDS@ RData are structurally identical.
type T_ds      = X_ds N_ds
type T_cds     = X_ds N_cds

-- | Interpret an 'X_ds' structure of type @DS@ as a 'T_ds'.
{-# COMPLETE T_DS #-}
pattern  T_DS :: Word16 -> DNSKEYAlg -> DSHashAlg -> ShortByteString -> T_ds
pattern  T_DS kt ka ha hv = (X_DS kt ka ha hv :: T_ds)
-- | Interpret an 'X_ds' structure of type @CDS@ as a 'T_cds'.
{-# COMPLETE T_CDS #-}
pattern T_CDS :: Word16 -> DNSKEYAlg -> DSHashAlg -> ShortByteString -> T_cds
pattern T_CDS kt ka ha hv = (X_DS kt ka ha hv :: T_cds)

-- | @KEY@, @DNSKEY@ and @CNSKEYS@ RData are structurally identical.
type T_key     = X_key N_key
type T_dnskey  = X_key N_dnskey
type T_cdnskey = X_key N_cdnskey

-- | Interpret an 'X_key' structure of type @KEY@ as a 'T_key'.
{-# COMPLETE T_KEY #-}
pattern     T_KEY :: Word16 -> Word8 -> DNSKEYAlg -> ShortByteString ->  T_key
pattern     T_KEY kf kp ka kk = (X_KEY kf kp ka kk :: T_key)
--
-- | Interpret an 'X_key' structure of type @DNSKEY@ as a 'T_dnskey'.
{-# COMPLETE T_DNSKEY #-}
pattern  T_DNSKEY :: Word16 -> Word8 -> DNSKEYAlg -> ShortByteString ->  T_dnskey
pattern  T_DNSKEY kf kp ka kk = (X_KEY kf kp ka kk :: T_dnskey)
--
-- | Interpret an 'X_key' structure of type @CDNSKEY@ as a 'T_cdnskey'.
{-# COMPLETE T_CDNSKEY #-}
pattern T_CDNSKEY :: Word16 -> Word8 -> DNSKEYAlg -> ShortByteString -> T_cdnskey
pattern T_CDNSKEY kf kp ka kk = (X_KEY kf kp ka kk :: T_cdnskey)

-- | @SIG@ and @RRSIG@ RData are structurally identical.
type T_rrsig = X_sig N_rrsig
type T_sig   = X_sig N_sig

-- | Interpret an 'X_sig' structure of type @SIG@ as a 'T_sig'.
{-# COMPLETE T_SIG #-}
pattern T_SIG :: RRTYPE -> DNSKEYAlg -> Word8 -> Word32 -> Int64
              -> Int64 -> Word16 -> Domain -> ShortByteString -> T_sig
pattern T_SIG ty sa sl st se si stg sz sv =
    (X_SIG ty sa sl st se si stg sz sv :: T_sig)
--
-- | Interpret an 'X_sig' structure of type @RRSIG@ as a 'T_rrsig'.
{-# COMPLETE T_RRSIG #-}
pattern T_RRSIG :: RRTYPE -> DNSKEYAlg -> Word8 -> Word32 -> Int64
                -> Int64 -> Word16 -> Domain -> ShortByteString -> T_rrsig
pattern T_RRSIG ty sa sl st se si stg sz sv =
    (X_SIG ty sa sl st se si stg sz sv :: T_rrsig)

-------------------
-- RData structure Definitions

-- | [DS RDATA](https://tools.ietf.org/html/rfc4034#section-5.1).
-- DNSSEC Delegation Signer.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |           Key Tag             |  Algorithm    |  Digest Type  |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > /                                                               /
-- > /                            Digest                             /
-- > /                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- Ordered canonically:
-- [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)
--
-- Published on the parent side of each signed delegation.  Shares its
-- representation with @CDS@, and the two types are mutually coercible.
-- The shared 'X_ds' constructor supports record syntax:
--
-- > :set -XOverloadedStrings
-- > let ds  :: T_ds
-- >     cds :: T_cds
-- >     ds  = X_DS { dsKtag 12345
-- >                , dsKalg 13
-- >                , dsHalg 2
-- >                , dsHval = coerce @Bytes16 "0001...1e1f" }
-- >     cds = X_DS { dsKtag 12345
-- >                , dsKalg 13
-- >                , dsHalg 2
-- >                , dsHval = coerce @Bytes16 "0001...1e1f" }
--
-- But the result type must generally either be specified explicitly, or be
-- possible for the compiler to infer from context.  In the example below, the
-- explicit type is not optional, because @RData rd@ could hold either type.
--
-- > :set -XOverloadedStrings
-- > let rd :: T_ds
-- >     rd = X_DS { dsKtag 12345
-- >               , dsKalg 13
-- >               , dsHalg 2
-- >               , dsHval = coerce @Bytes16 "0001...1e1f" }
-- >  in RData rd
--
-- Functions that are agnostic of the underlying type can be written as:
--
-- > hashTypeVal :: forall n. X_ds n -> (Word8, ShortByteString)
-- > hashTypeVal = (,) <$> dsHalg <*> dsHval
--
type X_ds :: Nat -> Type
data X_ds n = X_DS
    { dsKtag :: Word16
    , dsKalg :: DNSKEYAlg
    , dsHalg :: DSHashAlg
    , dsHval :: ShortByteString
    }
deriving instance (KnownSymbol (XdsConName n)) => Typeable (X_ds n)
deriving instance (KnownSymbol (XdsConName n)) => Eq (X_ds n)
deriving instance (KnownSymbol (XdsConName n)) => Ord (X_ds n)

instance (Nat16 n, KnownSymbol (XdsConName n)) => Show (X_ds n) where
    showsPrec p X_DS{..} = showsP p $
        showString (symbolVal (Proxy @(XdsConName n))) . showChar ' '
        . shows' dsKtag     . showChar ' '
        . shows' dsKalg     . showChar ' '
        . shows' dsHalg     . showChar ' '
        . showHv dsHval
      where
        showHv = shows @Bytes16 . coerce

instance (KnownSymbol (XdsConName n)) => Presentable (X_ds n) where
    present X_DS{..} =
        present     dsKtag
        . presentSp dsKalg
        . presentSp dsHalg
        . presentHv dsHval
      where
        presentHv = presentSp @Bytes16 . coerce

instance (Nat16 n, KnownSymbol (XdsConName n)) => KnownRData (X_ds n) where
    rdType = RRTYPE $ natToWord16 @n
    {-# INLINE rdType #-}
    rdEncode X_DS{..} = putSizedBuilder $!
           mbWord16       dsKtag
        <> coerce mbWord8 dsKalg
        <> coerce mbWord8 dsHalg
        <> mbShortByteString dsHval
    rdDecode _ len = do
        dsKtag <- get16
        dsKalg <- DNSKEYAlg <$> get8
        dsHalg <- DSHashAlg <$> get8
        dsHval <- getShortNByteString (len - 4)
        pure $ RData (X_DS{..} :: X_ds n)

-- | [DNSKEY RDATA](https://tools.ietf.org/html/rfc4034#section-2).
-- DNSSEC signing key:
--
-- >                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >  |              Flags            |    Protocol   |   Algorithm   |
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >  /                                                               /
-- >  /                            Public Key                         /
-- >  /                                                               /
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- Ordered canonically:
-- [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)
--
-- Published at the child zone apex of each signed zone.  The data type shares
-- its representation with
-- [CDNSKEY](https://www.rfc-editor.org/rfc/rfc7344.html#section-3.2), and also
-- the legacy [KEY](https://www.rfc-editor.org/rfc/rfc2535#section-3.1) RRtype.
-- The three types are mutually coercible.  The shared 'X_KEY' constructor
-- supports record syntax:
--
-- > :set -XOverloadedStrings
-- > let dk  :: T_dnskey
-- >     cdk :: T_cdnskey
-- >     dk   = X_KEY { keyFlags = 257
-- >                  , keyProto = 3
-- >                  , keyAlgor = 13
-- >                  , keyValue = coerce @Bytes64 "3FOs...Kw==" }
-- >     cdk  = X_KEY { keyFlags = 257
-- >                  , keyProto = 3
-- >                  , keyAlgor = 13
-- >                  , keyValue = coerce @Bytes64 "3FOs...Kw==" }
--
-- But the result type must generally either be specified explicitly, or be
-- possible for the compiler to infer from context.  In the example below, the
-- explicit type is not optional, because @RData rd@ could hold either type.
--
-- > :set -XOverloadedStrings
-- > let rd :: T_dnskey
-- >     rd = X_KEY { keyFlags = 257
-- >                , keyProto = 3
-- >                , keyAlgor = 13
-- >                , keyValue = coerce @Bytes64 "3FOs...Kw==" }
-- >  in RData rd
--
-- Functions that are agnostic of the underlying type can be written as:
--
-- > keyAlgVal :: forall n. X_key n -> (Word8, ShortByteString)
-- > keyAlgVal = (,) <$> keyAlgor <*> keyValue
--
type X_key :: Nat -> Type
data X_key n = X_KEY
    { keyFlags :: Word16
    , keyProto :: Word8
    , keyAlgor :: DNSKEYAlg
    , keyValue :: ShortByteString
    }
deriving instance (KnownSymbol (XkeyConName n)) => Typeable (X_key n)
deriving instance (KnownSymbol (XkeyConName n)) => Eq (X_key n)
deriving instance (KnownSymbol (XkeyConName n)) => Ord (X_key n)

instance (Nat16 n, KnownSymbol (XkeyConName n)) => Show (X_key n) where
    showsPrec p X_KEY{..} = showsP p $
        showString (symbolVal (Proxy @(XkeyConName n))) . showChar ' '
        . shows' keyFlags    . showChar ' '
        . shows' keyProto    . showChar ' '
        . shows' keyAlgor    . showChar ' '
        . showKv keyValue
      where
        showKv = shows @Bytes64 . coerce

instance (KnownSymbol (XkeyConName n)) => Presentable (X_key n) where
    present X_KEY{..} =
        present     keyFlags
        . presentSp keyProto
        . presentSp keyAlgor
        . presentKv keyValue
      where
        presentKv = presentSp @Bytes64 . coerce

instance (Nat16 n, KnownSymbol (XkeyConName n)) => KnownRData (X_key n) where
    rdType = RRTYPE $ natToWord16 @n
    {-# INLINE rdType #-}
    rdEncode X_KEY{..} = putSizedBuilder $!
        mbWord16   keyFlags
        <> mbWord8 keyProto
        <> coerce mbWord8 keyAlgor
        <> mbShortByteString keyValue
    rdDecode _ len = do
        keyFlags <- get16
        keyProto <- get8
        keyAlgor <- DNSKEYAlg <$> get8
        keyValue <- getShortNByteString (len - 4)
        pure $ RData (X_KEY{..} :: X_key n)

-- | [RRSIG RDATA](https://tools.ietf.org/html/rfc4034#section-3).
-- DNSSEC signature.  This type also represents the obsolete
-- [SIG](https://www.rfc-editor.org/rfc/rfc2535#section-4.1), and, still used,
-- [SIG(0)](https://www.rfc-editor.org/rfc/rfc2931.html#section-3) records.
-- The three types are mutually coercible and share a common constructor and
-- record syntax.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |        type covered           |  algorithm    |     labels    |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                         original TTL                          |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                      signature expiration                     |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                      signature inception                      |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |            key  tag           |                               |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         signer's name         +
-- > |                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
-- > /                                                               /
-- > /                            signature                          /
-- > /                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- As noted in
-- [Section 3.1.5 of RFC 4034](https://tools.ietf.org/html/rfc4034#section-3.1.5)
-- the RRsig inception and expiration times use serial number arithmetic.  As a
-- result these timestamps /are not/ pure values, their meaning is
-- time-dependent!  They depend on the present time and are both at most
-- approximately +\/-68 years from the present.  This ambiguity is not a
-- problem because cached RRSIG records should only persist a few days,
-- signature lifetimes should be *much* shorter than 68 years, and key rotation
-- should cause any misconstrued 136-year-old signatures to fail to validate.
-- This also means that the interpretation of a time that is exactly half-way
-- around the clock at @now +\/-0x80000000@ is not important, the signature
-- should never be valid.
--
-- To avoid ambiguity, these *impure* relative values are converted to pure
-- absolute times as they are received from from the network, and converted
-- back to 32-bit values when encoding.  Therefore, the constructor takes
-- absolute 64-bit representations of the inception and expiration times.
--
-- The 'dnsTime' function performs the requisite conversion.
--
-- The signer zone name is not subject to
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4),
-- but canonicalises to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2),
-- [RFC6840](https://datatracker.ietf.org/doc/html/rfc6840#section-5.1)
--
-- The 'Ord' instance is not canonical.  Canonical ordering requires
-- serialisation to canonical wire form.
--
type role X_sig phantom
type X_sig :: Nat -> Type
data X_sig n = X_SIG
    { sigType       :: RRTYPE          -- ^ RRtype of RRset signed
    , sigKeyAlg     :: DNSKEYAlg       -- ^ DNSKEY algorithm
    , sigNumLabels  :: Word8           -- ^ Number of labels signed
    , sigTTL        :: Word32          -- ^ Maximum origin TTL
    , sigExpiration :: Int64           -- ^ Time last valid
    , sigInception  :: Int64           -- ^ Time first valid
    , sigKeyTag     :: Word16          -- ^ Signing key tag
    , sigZone       :: Domain          -- ^ Signing domain
    , sigValue      :: ShortByteString -- ^ Opaque signature
    }
deriving instance (KnownSymbol (XsigConName n)) => Typeable (X_sig n)

instance (Nat16 n, KnownSymbol (XsigConName n)) => Show (X_sig n) where
    showsPrec p X_SIG{..} = showsP p $
        showString (symbolVal (Proxy @(XsigConName n))) . showChar ' '
        . shows' sigType       . showChar ' '
        . shows' sigKeyAlg     . showChar ' '
        . shows' sigNumLabels  . showChar ' '
        . shows' sigTTL        . showChar ' '
        . shows' sigExpiration . showChar ' '
        . shows' sigInception  . showChar ' '
        . shows' sigKeyTag     . showChar ' '
        . shows' sigZone       . showChar ' '
        . showSv sigValue
      where
        showSv = shows @Bytes64 . coerce

-- | Equality of signer names is case-insensitive.
instance (KnownSymbol (XsigConName n)) => Eq  (X_sig n) where
    a == b = (sigType       a) == (sigType       b)
          && (sigKeyAlg     a) == (sigKeyAlg     b)
          && (sigNumLabels  a) == (sigNumLabels  b)
          && (sigTTL        a) == (sigTTL        b)
          && (sigExpiration a) == (sigExpiration b)
          && (sigInception  a) == (sigInception  b)
          && (sigKeyTag     a) == (sigKeyTag     b)
          && (sigZone a) `equalWireHost` (sigZone b)
          && (sigValue      a) == (sigValue      b)

-- | Comparison of signer names is case-insensitive.
instance (KnownSymbol (XsigConName n)) => Ord (X_sig n) where
    a `compare` b = (sigType       a) `compare` (sigType       b)
                 <> (sigKeyAlg     a) `compare` (sigKeyAlg     b)
                 <> (sigNumLabels  a) `compare` (sigNumLabels  b)
                 <> (sigTTL        a) `compare` (sigTTL        b)
                 <> (sigExpiration a) `compare` (sigExpiration b)
                 <> (sigInception  a) `compare` (sigInception  b)
                 <> (sigKeyTag     a) `compare` (sigKeyTag     b)
                 <> (sigZone a) `compareWireHost` (sigZone     b)
                 <> (sigValue      a) `compare` (sigValue      b)

instance (KnownSymbol (XsigConName n)) => Presentable (X_sig n) where
    present X_SIG{..} =
        present     sigType
        . presentSp sigKeyAlg
        . presentSp sigNumLabels
        . presentSp sigTTL
        . presentEp sigExpiration
        . presentEp sigInception
        . presentSp sigKeyTag
        . presentSp sigZone
        . presentSv sigValue
      where
        presentEp = presentSp @Epoch64 . coerce
        presentSv = presentSp @Bytes64 . coerce

instance (Nat16 n, KnownSymbol (XsigConName n)) => KnownRData (X_sig n) where
    rdType = RRTYPE $ natToWord16 @n
    {-# INLINE rdType #-}
    rdEncode X_SIG{..} = putSizedBuilder $
        coerce mbWord16     sigType
        <> coerce mbWord8   sigKeyAlg
        <> mbWord8          sigNumLabels
        <> mbWord32         sigTTL
        <> coerce clock     sigExpiration
        <> coerce clock     sigInception
        <> mbWord16         sigKeyTag
        <> mbWireForm       sigZone
        <> mbShortByteString sigValue
      where
        clock :: Int64 -> SizedBuilder
        clock = mbWord32 . fromIntegral
    cnEncode X_SIG{..} = putSizedBuilder $
        coerce mbWord16     sigType
        <> coerce mbWord8   sigKeyAlg
        <> mbWord8          sigNumLabels
        <> mbWord32         sigTTL
        <> coerce clock     sigExpiration
        <> coerce clock     sigInception
        <> mbWord16         sigKeyTag
        <> mbWireForm (canonicalise sigZone)
        -- | Canonical encoding of the RRSIG omits the signature value.
      where
        clock :: Int64 -> SizedBuilder
        clock = mbWord32 . fromIntegral
    rdDecode _ len = do
        pos0          <- getPosition
        sigType       <- RRTYPE <$> get16
        sigKeyAlg     <- DNSKEYAlg <$> get8
        sigNumLabels  <- get8
        sigTTL        <- get32
        sigExpiration <- getDnsTime
        sigInception  <- getDnsTime
        sigKeyTag     <- get16
        sigZone       <- getDomainNC
        used          <- (subtract pos0) <$> getPosition
        sigValue      <- getShortNByteString (len - used)
        pure $ RData (X_SIG{..} :: X_sig n)

-- | [ZONEMD RDATA](https://www.rfc-editor.org/rfc/rfc8976.html#section-2.2).
-- Message Digest for DNS Zones.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                             Serial                            |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |    Scheme     |Hash Algorithm |                               |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
-- > |                             Digest                            |
-- > /                                                               /
-- > /                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- Ordered canonically.
--
data T_zonemd = T_ZONEMD
    { zonemdSerial  :: Word32
    , zonemdScheme  :: Word8
    , zonemdHashAlg :: Word8
    , zonemdDigest  :: ShortByteString
    } deriving (Typeable, Eq, Ord)

instance Show T_zonemd where
    showsPrec p T_ZONEMD{..} = showsP p $
        showString "X_SIG"     . showChar ' '
        . shows' zonemdSerial  . showChar ' '
        . shows' zonemdScheme  . showChar ' '
        . shows' zonemdHashAlg . showChar ' '
        . showMd zonemdDigest
      where
        showMd = shows @Bytes16 . coerce

instance Presentable T_zonemd where
    present T_ZONEMD{..} =
        present   zonemdSerial
        . presentSp zonemdScheme
        . presentSp zonemdHashAlg
        . presentMd zonemdDigest
      where
        presentMd d | SB.null d = present @String " ( )"
                    | otherwise = presentSp @Bytes16 (coerce d)

instance KnownRData T_zonemd where
    rdType     = ZONEMD
    {-# INLINE rdType #-}
    rdEncode T_ZONEMD{..}
        | SB.length (coerce zonemdDigest) < 12
        = failWith CantEncode
        | otherwise
        = putSizedBuilder $
            mbWord32 zonemdSerial
            <> mbWord8 zonemdScheme
            <> mbWord8 zonemdHashAlg
            <> mbShortByteString zonemdDigest
    rdDecode _ len | len < 18 = failSGet "ZONEMD digest too short"
    rdDecode _ len = do
        zonemdSerial    <- get32
        zonemdScheme    <- get8
        zonemdHashAlg   <- get8
        zonemdDigest    <- getShortNByteString (len - 6)
        pure $ RData T_ZONEMD{..}

-- | Compute RFC 4034, Appendix B key tag over the DNSKEY RData: 16 bit flags,
-- 8 bit proto, 8 bit alg and key octets.
--
-- With the obsolete algorithm 1 we assign key tag 0 to truncated keys, but
-- RSAMD5 keys are no longer seen in the wild.  We check that the modulus
-- actually has at least 3 octets.
--
keytag :: X_key n -> Word16
keytag = fromIntegral . go
  where
    go :: X_key n -> Word32
    go X_KEY{..} | alg /= 1 = tag
      where
        (DNSKEYAlg alg) = keyAlgor
        !z   = lo keyFlags + hi keyProto + lo alg
        ws32 = zipWith ($) (cycle [hi, lo]) $ SB.unpack keyValue
        !raw = foldl' (+) z ws32
        !tag = (raw + (raw `shiftR` 16)) .&. 0xffff
    go X_KEY{..} | Just !tag <- c32 = tag
                    | otherwise = 0
      where
        len = SB.length keyValue
        c32 = (+) <$> (hi <$.> SB.indexMaybe keyValue (len - 3))
                  <*> (lo <$.> SB.indexMaybe keyValue (len - 2))

    hi, lo :: Integral a => a -> Word32
    lo = fromIntegral
    hi = flip shiftL 8 . lo
