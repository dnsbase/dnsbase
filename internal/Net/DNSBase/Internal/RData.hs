{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.Internal.RData
    ( -- * RData class
      RData(..)
    , KnownRData(..)
    , SomeCodec(..)
    , RDataMap
    , fromRData
    , monoRData
    , rdataType
    , rdataEncode
    , rdataEncodeCanonical
      -- ** Opaque RData
    , OpaqueRData(..)
    , opaqueRData
    , toOpaque
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Short as SB
import Data.IntMap (IntMap)

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.Bytes
import Net.DNSBase.Internal.Nat16
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.Util

-- | Abstract DNS Resource Record (type-specific) data.
--
-- The decoding, encoding and presentation functions are responsible for just
-- the value, decoding, encoding or presenting the type happens at a different
-- layer.  The 'Show' instance is typically derived, and will output the type
-- constructor (its output strives to produce syntactically valid Haskell
-- values), in contrast with 'Presentable' which produces RFC-standard
-- presentation forms.
class (Typeable a, Eq a, Ord a, Show a, Presentable a) => KnownRData a where
    -- | Tunable parameters for decoding extension types such, e.g., @SVCB@
    type CodecOpts a :: Type
    optUpdate :: forall b -> b ~ a => CodecOpts a -> CodecOpts a -> CodecOpts a
    -- | Default no options
    type CodecOpts a = ()
    optUpdate _ = const

    rdType     :: forall b -> b ~ a => RRTYPE
    rdTypePres :: forall b -> b ~ a => Builder -> Builder
    rdDecode   :: forall b -> b ~ a => CodecOpts a -> Int -> SGet RData
    -- Default encoding
    rdEncode   :: a -> SPut s RData
    -- Canonical encoding for DNSSEC validation.
    cnEncode   :: a -> SPut s RData
    cnEncode    = rdEncode

    -- | Override for user-friendly types for non-built-in types added at
    -- runtime (as part of resolver configuration).  Otherwise, defaults to
    -- @TYPE@/number/.
    rdTypePres _ = present $ rdType a
    {-# INLINE rdTypePres #-}

-- | Wrapper around any concrete 'KnownRData' type.
--
-- Its presentation form includes both the type and the value, space-separated.
-- The underlying concrete types present just their values.
data RData = forall a. KnownRData a => RData a

-- | Extract specific known 'RData' from existential wrapping
fromRData  :: forall a. KnownRData a => RData -> Maybe a
fromRData (RData a) = cast a
{-# INLINE fromRData #-}

instance Show RData where
    showsPrec p (RData a) = showsP p $ showString "RData " . shows' a

-- | Presents the type and value, space-separated.
instance Presentable RData where
    present (RData (a :: t)) = rdTypePres t . presentSp a

-- | Known RData Proxy + Codec parameter pair
data SomeCodec where
    SomeCodec :: KnownRData a
              => Proxy a
              -> CodecOpts a
              -> SomeCodec

-- | Map associating a type-specific length-aware 'RData' decoder
-- to each 'RRTYPE'
type RDataMap = IntMap SomeCodec

-- | Returns a monomorphic sub-list of a collection of 'RData' elements.
monoRData :: forall a t. (KnownRData a, Foldable t) => t RData -> [a]
monoRData = foldr (maybe id (:) . fromRData) []
{-# INLINE monoRData #-}

{-# INLINE rdataType #-}
rdataType :: RData -> RRTYPE
rdataType (RData (_ :: t)) = rdType t

instance Eq RData where
    (RData (_a :: a)) == (RData (_b :: b)) =
        case teq a b of
            Just Refl -> _a == _b
            _         -> False

-- | Compare RData first by RRtype number, then by content.
-- When two RRtype numbers match, but the data types nevertheless differ, order
-- opaque type after non-opaque.  In the unlikely case of two non-opaque types
-- with the same RRtype, compare their opaque encodings (this could throw an
-- error if one of the objects is not encodable, perhaps because encoding would
-- be too long).
instance Ord RData where
    ra@(RData (_a :: a)) `compare` rb@(RData (_b :: b)) =
        compare (rdType a) (rdType b)
        <> if | Just Refl <- teq a b -> compare _a _b
              | isOpaque (rdType a) ra -> GT
              | isOpaque (rdType b) rb -> LT
              | otherwise      -> ocmp (toOpaque ra) (toOpaque rb)
      where
        ocmp (Right oa) (Right ob) = compare oa ob
        ocmp (Left e)   _          = error $ show e
        ocmp _          (Left e)   = error $ show e

-- | Perform a default encoding of the contained 'KnownRData'.
rdataEncode :: RData -> SPut s RData
rdataEncode rd@(RData a) = setContext rd $ rdEncode a

-- | Perform a canonical encoding of the contained 'KnownRData'.
rdataEncodeCanonical :: RData -> SPut s RData
rdataEncodeCanonical rd@(RData a) = setContext rd $ cnEncode a

-- | Opaque 'RData', for RRTYPEs not known at runtime
--
data OpaqueRData n = Nat16 n => OpaqueRData ShortByteString
deriving instance Eq (OpaqueRData n)
deriving instance Ord (OpaqueRData n)
instance Show (OpaqueRData n) where
    showsPrec p (OpaqueRData bs) = showsP p $
        showString "OpaqueRData @"
        . shows (natToWord16 n) . showChar ' '
        . shows @Bytes16 (coerce bs)

instance Presentable (OpaqueRData n) where
    present (OpaqueRData val) =
        present "\\#"
        . presentSp (SB.length val)
        . present16 val
      where
        present16 = presentSp @Bytes16 . coerce

instance Nat16 n => KnownRData (OpaqueRData n) where
    rdType _ = RRTYPE $ natToWord16 n
    rdTypePres _ = present "TYPE"
                 . present (natToWord16 n)
    rdEncode (OpaqueRData bs) = putShortByteString bs
    rdDecode _ _ len = do
      bs <- getShortNByteString len
      return $ RData $ (OpaqueRData bs :: OpaqueRData n)

-- | Create opaque RData from its type number and Bytes16 value
opaqueRData :: Word16 -> ShortByteString -> RData
opaqueRData w bs = withNat16 w go
  where
    go :: forall (n :: Nat) -> Nat16 n => RData
    go n = RData $ (OpaqueRData bs :: OpaqueRData n)

-- | Convert 'RData' to its 'Opaque' equivalent of the same RRtype.
-- 'OpaqueRData' values will be returned as-is.  Otherwise, this will attempt
-- to encode the record without name compression, the encoding may fail, in
-- which case the return value will be 'Nothing'.
--
toOpaque :: RData -> Either (EncodeErr (Maybe RData)) RData
toOpaque rd@(rdataType -> rt) = withNat16 (coerce rt) go
  where
    go :: forall (n :: Nat) -> Nat16 n => Either (EncodeErr (Maybe RData)) RData
    go n | isOpaque rt rd = Right rd
         | otherwise
           = RData . mkopaque <$> encodeVerbatim do rdataEncode rd
             where
               mkopaque :: B.ByteString -> OpaqueRData n
               mkopaque bs = OpaqueRData $ SB.toShort bs

-- | Check whether the given 'RData' is opaque of given RRtype.
--
isOpaque :: RRTYPE -> RData -> Bool
isOpaque rt rd = withNat16 (coerce rt) go
  where
    go :: forall (n :: Nat) -> Nat16 n => Bool
    go n = isJust (fromRData rd :: Maybe (OpaqueRData n))
