{-|
Module      : Net.DNSBase.RData.SVCB.SVCParamValue
Description : Typed values for SVCB / HTTPS service-parameter keys
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

An @SVCB@ or @HTTPS@ record carries a list of (key, value) service
parameters.  Each key has its own value type, so the value side is
structured as an extensible typeclass 'KnownSVCParamValue' with
one instance per standardised key, wrapped in an existential
'SVCParamValue' so a single list can hold a heterogeneous mix.
Unknown keys fall through to 'OpaqueSPV', which preserves the raw
wire bytes for later inspection or pass-through.

Applications can add a new service-parameter type at runtime by
writing a 'KnownSVCParamValue' instance and installing it via
'Net.DNSBase.Resolver.extendRRwithType' on the @SVCB@ or @HTTPS@
RR type — see "Net.DNSBase.Extensible" for a worked example.
-}

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

import qualified Data.ByteString.Short as SB
import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.State
import Net.DNSBase.Nat16
import Net.DNSBase.Present
import Net.DNSBase.RData.SVCB.SVCParamKey
import Net.DNSBase.Text

-- * Generic SVC Field-Value

-- | The class of types representing the value side of a service
-- parameter inside an @SVCB@ or @HTTPS@ record.  Each instance
-- corresponds to a specific 'SVCParamKey'; the 'encodeSPV' and
-- 'decodeSPV' methods handle only the value bytes.
--
-- The 'Presentable' instance builds the RFC 9460 zone-file
-- presentation form: the key name followed (where the value is
-- non-empty) by @=@ and the value.  The 'Show' instance is
-- typically derived and aims to produce syntactically valid
-- Haskell.
class (Typeable a, Eq a, Ord a, Show a, Presentable a) => KnownSVCParamValue a where
    -- | The associated key number
    spvKey     :: forall b -> b ~ a => SVCParamKey
    -- | CPS presentation form builder for the key
    spvKeyPres :: forall b -> b ~ a => Builder -> Builder

    -- | Encode value to wire form.
    -- The surrounding @(key, length)@ frame is owned by the
    -- SVCB-record encoder: 'encodeSPV' writes just the payload,
    -- and the framework wraps the result in the 2-byte length
    -- prefix.  For valueless parameters this means 'encodeSPV'
    -- is just @pure ()@.
    --
    encodeSPV  :: forall r s. ErrorContext r => a -> SPut s r

    -- | Decode value from wire form.
    -- The overall SVCB RData decoder gives each parameter decoder
    -- a view into a buffer of exactly the indicated length, and
    -- makes sure exactly that many bytes are consumed.  The
    -- length argument is only needed in decoders that read
    -- variable-length fields that run to the end of the record.
    --
    decodeSPV  :: forall b -> b ~ a => Int -> SGet SVCParamValue

    -- | Override to get user-friendly output for runtime-added types.
    -- Otherwise, defaults to @key@/number/.
    spvKeyPres _ = present (spvKey a)


-- | Existential wrapper around any 'KnownSVCParamValue', so a
-- single list can hold a mix of typed service parameters.  The
-- 'present' method delegates to the underlying instance, which
-- emits both the key name and the value.
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

-- | Fallback carrier for service-parameter values whose key code
-- has no 'KnownSVCParamValue' instance registered.  The key code
-- is encoded as a type-level natural so 'OpaqueSPV' values with
-- different codes have distinct types.  The wire payload is kept
-- as raw bytes and round-trips losslessly; the presentation form
-- is @keyN=...@ with the value as a 'DnsText' character-string.
newtype OpaqueSPV n = OpaqueSPV SB.ShortByteString
type OpaqueSPV :: Nat -> Type
type role OpaqueSPV nominal

deriving instance Eq (OpaqueSPV n)
deriving instance Ord (OpaqueSPV n)
deriving instance Show (OpaqueSPV n)

instance Nat16 n => KnownSVCParamValue (OpaqueSPV n) where
    spvKey _ = SVCParamKey $ natToWord16 n
    encodeSPV (OpaqueSPV txt) = putShortByteString txt
    decodeSPV _ = SVCParamValue . OpaqueSPV @n <.> getShortNByteString

instance Nat16 n => Presentable (OpaqueSPV n) where
    present (OpaqueSPV v) =
        present "key" . present (natToWord16 n)
        -- Empty values suppressed
        . bool id (presentCharSep @DnsText '=' (coerce v)) ((SB.length v) > 0)

-- | Build an 'SVCParamValue' from a raw numeric key and a raw
-- byte payload.  Useful when a caller has a wire encoding for a
-- key that has no registered 'KnownSVCParamValue' instance, or
-- when round-tripping bytes for keys that should remain
-- uninterpreted.
opaqueSPV :: Word16 -> SB.ShortByteString -> SVCParamValue
opaqueSPV w bs = withNat16 w go
  where
    go :: forall (n :: Nat) -> Nat16 n => SVCParamValue
    go n = SVCParamValue $ (OpaqueSPV bs :: OpaqueSPV n)

-- | Encode an 'SVCParamValue' to its 'OpaqueSPV' equivalent under
-- the same key code.  Values that are already opaque are returned
-- unchanged.  For typed values this re-encodes the payload to
-- wire form; encoding can fail (for example if the result would
-- be too long to fit a 16-bit length field), in which case the
-- 'EncodeErr' is returned.
toOpaqueSPV :: SVCParamValue -> Either (EncodeErr (Maybe ())) SVCParamValue
toOpaqueSPV s@(svcParamValueKey -> k) = withNat16 (coerce k) go
  where
    go :: forall (n :: Nat) -> Nat16 n
       => Either (EncodeErr (Maybe ())) SVCParamValue
    go n | isOpaque k s = Right s
         | otherwise
           = SVCParamValue . mkopaque <$> encodeVerbatim do spvEncode s
             where
               -- Raw value bytes (the SVCB framework supplies the
               -- 2-byte length prefix on the wire, but here we are
               -- capturing just the payload for opaque storage).
               mkopaque :: ByteString -> OpaqueSPV n
               mkopaque bs = OpaqueSPV $ SB.toShort bs

-- | Check whether the given 'SVCParamValue is opaque of given key.
--
isOpaque :: SVCParamKey -> SVCParamValue -> Bool
isOpaque k spv = withNat16 (coerce k) go
  where
    go :: forall (n :: Nat) -> Nat16 n => Bool
    go n = isJust (fromSPV spv :: Maybe (OpaqueSPV n))
