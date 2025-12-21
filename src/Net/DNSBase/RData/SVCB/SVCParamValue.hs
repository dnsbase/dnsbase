module Net.DNSBase.RData.SVCB.SVCParamValue
    ( KnownSVCParamValue(..)
    , SVCParamValue(..)
    , fromSPV
    , serviceParamKey
      -- Representation of unknown parameters
    , OpaqueSPV(..)
    , opaqueSPV
    , toOpaqueSPV
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Short as SB
import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.State
import Net.DNSBase.Nat16
import Net.DNSBase.Present
import Net.DNSBase.RData.SVCB.SVCParamKey
import Net.DNSBase.Text

-- * Generic SVC Field-Value

-- | Service Binding (SVCB) Parameter class.
--
-- The decoding and encoding functions are responsible for just the value,
-- decoding or encoding the key happens at a different layer.  The 'Show'
-- instance is typically derived, and will output the type constructor (its
-- output strives to produce syntactically valid Haskell values).  The
-- 'Presentable' instance builds RFC-standard presentation forms of the key and
-- optional value (separated by @=@ when there's a value).
class (Typeable a, Eq a, Ord a, Show a, Presentable a) => KnownSVCParamValue a where
    spvKey     :: forall b -> b ~ a => SVCParamKey
    spvKeyPres :: forall b -> b ~ a => Builder -> Builder
    encodeSPV  :: forall r s. ErrorContext r => a -> SPut s r
    decodeSPV  :: forall b -> b ~ a => Int -> SGet SVCParamValue

    -- | Override to get user-friendly output for runtime-added types.
    -- Otherwise, defaults to @key@/number/.
    spvKeyPres _ = present (spvKey a)


-- | Wrapper around any concrete @SVCB@ parameter type.
--
-- Its 'present' method just invokes 'present' on the underlying parameter,
-- which is also responsible for presenting the key.
data SVCParamValue = forall a. KnownSVCParamValue a => SVCParamValue a

-- | Extract specific known 'SVCParamValue' from existential wrapping
fromSPV :: forall a. KnownSVCParamValue a => SVCParamValue -> Maybe a
fromSPV (SVCParamValue a) = cast a

svcParamValueKey :: SVCParamValue -> SVCParamKey
svcParamValueKey (SVCParamValue (_ :: t)) = spvKey t
{-# INLINE svcParamValueKey #-}

-- | Perform a default encoding of the contained 'KnownSVCParamValue'.
spvEncode :: ErrorContext r => SVCParamValue -> SPut s r
spvEncode (SVCParamValue a) = encodeSPV a

-- | Key associated with a generic SvcParamValue
serviceParamKey :: SVCParamValue -> SVCParamKey
serviceParamKey (SVCParamValue (_ :: t)) = spvKey t

instance Eq SVCParamValue where
    (SVCParamValue (_a :: a)) == (SVCParamValue (_b :: b))
        | spvKey a /= spvKey b = False
        | Just Refl <- teq a b = _a == _b
        | otherwise = False

-- | Compare first by key number, then by content.
-- When two key numbers match, but the data types nevertheless differ, order
-- opaque type after non-opaque.  In the unlikely case of two non-opaque types
-- with the same key, compare their opaque encodings (this could throw an error
-- if one of the objects is not encodable, perhaps because encoding would be
-- too long).
instance Ord SVCParamValue where
    compare sa@(SVCParamValue (_a :: a)) sb@(SVCParamValue (_b :: b)) =
        compare (spvKey a) (spvKey b)
        <> if | Just Refl <- teq a b -> compare _a _b
              | isOpaque (spvKey a) sa -> GT
              | isOpaque (spvKey b) sb -> LT
              | otherwise              -> ocmp (toOpaqueSPV sa) (toOpaqueSPV sb)
      where
        ocmp (Right oa) (Right ob) = compare oa ob
        ocmp (Left e)   _          = error $ show e
        ocmp _          (Left e)   = error $ show e

instance Show SVCParamValue where
    showsPrec p (SVCParamValue a) =
        showParen (p > app_prec) $
            showString "SVCParamValue "
            . showsPrec (app_prec + 1) a
      where
        app_prec = 10

instance Presentable SVCParamValue where
    present (SVCParamValue a)  = present a

-- | Opaque (i.e. unknown) ParamKey

data OpaqueSPV n where
     OpaqueSPV :: Nat16 n => SB.ShortByteString -> OpaqueSPV n
deriving instance Eq (OpaqueSPV n)
deriving instance Ord (OpaqueSPV n)
deriving instance Show (OpaqueSPV n)

instance Nat16 n => KnownSVCParamValue (OpaqueSPV n) where
    spvKey _ = SVCParamKey $ natToWord16 n
    encodeSPV (OpaqueSPV txt) = putShortByteStringLen16 txt
    decodeSPV _ len = do
        txt <- getShortNByteString len
        pure $ SVCParamValue (OpaqueSPV txt :: OpaqueSPV n)

instance Nat16 n => Presentable (OpaqueSPV n) where
    present (OpaqueSPV v) =
        present "key" . present (natToWord16 n)
        -- Empty values suppressed
        . bool id (presentCharSep @DnsText '=' (coerce v)) ((SB.length v) > 0)

-- | Construct an explicit 'OpaqueSPV' service parameter key value pair from
-- the raw numeric key and short bytestring value.
opaqueSPV :: Word16 -> SB.ShortByteString -> SVCParamValue
opaqueSPV w bs = withNat16 w go
  where
    go :: forall (n :: Nat) -> Nat16 n => SVCParamValue
    go n = SVCParamValue $ (OpaqueSPV bs :: OpaqueSPV n)

-- | Convert 'RData' to its 'Opaque' equivalent of the same RRtype.
-- 'OpaqueRData' values will be returned as-is.  Otherwise, this will attempt
-- to encode the record without name compression, the encoding may fail, in
-- which case the return value will be 'Nothing'.
--
toOpaqueSPV :: SVCParamValue -> Either (EncodeErr (Maybe ())) SVCParamValue
toOpaqueSPV s@(svcParamValueKey -> k) = withNat16 (coerce k) go
  where
    go :: forall (n :: Nat) -> Nat16 n
       => Either (EncodeErr (Maybe ())) SVCParamValue
    go n | isOpaque k s = Right s
         | otherwise
           = SVCParamValue . mkopaque <$> encodeVerbatim do spvEncode s
             where
               -- Wire form of value without its 2-byte length.
               mkopaque :: ByteString -> OpaqueSPV n
               mkopaque bs = OpaqueSPV $ SB.toShort $ B.drop 2 bs

-- | Check whether the given 'SVCParamValue is opaque of given key.
--
isOpaque :: SVCParamKey -> SVCParamValue -> Bool
isOpaque k spv = withNat16 (coerce k) go
  where
    go :: forall (n :: Nat) -> Nat16 n => Bool
    go n = isJust (fromSPV spv :: Maybe (OpaqueSPV n))
