{-# LANGUAGE
    DataKinds
  , MagicHash
  #-}

module Net.DNSBase.Internal.Nat16
    ( type Nat16
    , Nat
    , Typeable
    , natToWord16
    , withNat16
    )
    where

import Data.Kind (Constraint)
import Data.Typeable ((:~:)(Refl), Typeable)
import Data.Word (Word16)
import GHC.TypeNats ( Nat, CmpNat, KnownNat, SNat
                    , natVal', withSomeSNat, withKnownNat )
import GHC.Exts ( proxy# )
import Unsafe.Coerce (unsafeCoerce)

type Nat16 :: Nat -> Constraint
type Nat16 n = (KnownNat n, CmpNat n 65536 ~ LT)

-- | Convert 16-bit type-level natural to corresponding RRTYPE.
natToWord16 :: forall (n :: Nat) -> KnownNat n => Word16
natToWord16 n = fromIntegral $ natVal' @n proxy#
{-# INLINE natToWord16 #-}

-- | Convert RRTYPE to 16-bit natural @SomeNat@ singleton.
withNat16 :: forall r. Word16 -> (forall n -> Nat16 n => r) -> r
withNat16 w f = withSomeSNat (fromIntegral w) go
  where
    go :: forall n. SNat n -> r
    go s = case magic n of { Refl -> withKnownNat s (f n) }
    magic :: forall n -> CmpNat n 65536 :~: LT
    magic _ = unsafeCoerce (Refl @LT)
{-# INLINE withNat16 #-}
