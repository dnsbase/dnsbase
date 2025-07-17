{-# LANGUAGE RequiredTypeArguments #-}

module Net.DNSBase.RData.SVCB.SVCParamValue
    ( KnownSVCParamValue(..)
    , SVCParamValue(..)
    , serviceParamKey
    ) where

import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RData.SVCB.SVCParamKey

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
    fromSPV    :: SVCParamValue -> Maybe a
    encodeSPV  :: a -> SPut s RData
    decodeSPV  :: forall b -> b ~ a => Int -> SGet SVCParamValue

    -- | Override to get user-friendly output for runtime-added types.
    -- Otherwise, defaults to @key@/number/.
    spvKeyPres a = present (spvKey a)
    fromSPV (SVCParamValue a) = cast a


-- | Wrapper around any concrete @SVCB@ parameter type.
--
-- Its 'present' method just invokes 'present' on the underlying parameter,
-- which is also responsible for presenting the key.
data SVCParamValue = forall a. KnownSVCParamValue a => SVCParamValue a

-- | Key associated with a generic SvcParamValue
serviceParamKey :: SVCParamValue -> SVCParamKey
serviceParamKey (SVCParamValue (_ :: t)) = spvKey t

instance Eq SVCParamValue where
    (SVCParamValue (_a :: a)) == (SVCParamValue (_b :: b))
        | spvKey a /= spvKey b = False
        | Just Refl <- teq a b = _a == _b
        | otherwise = False

instance Ord SVCParamValue where
    compare (SVCParamValue (_a :: a)) (SVCParamValue (_b :: b)) =
        case compare (spvKey a) (spvKey b) of
            LT -> LT
            GT -> GT
            EQ | Just Refl <- teq a b -> compare _a _b
               | otherwise -> tcmp a b -- Presumably, opaque vs. non-opaque?

instance Show SVCParamValue where
    showsPrec p (SVCParamValue a) =
        showParen (p > app_prec) $
            showString "SVCParamValue "
            . showsPrec (app_prec + 1) a
      where
        app_prec = 10

instance Presentable SVCParamValue where
    present (SVCParamValue a)  = present a
