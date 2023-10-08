{-# LANGUAGE
    AllowAmbiguousTypes
  , MagicHash
  #-}
module Net.DNSBase.Internal.Nat16
    ( type Nat16
    , Nat
    , SomeNat16(..)
    , Typeable
    , natToWord16
    , wordToNat16
    )
    where

import Data.Kind (Constraint)
import Data.Proxy (Proxy(..))
import Data.Typeable ((:~:)(Refl), Typeable)
import Data.Word (Word16)
import GHC.TypeNats ( Nat, KnownNat, SomeNat(..)
                    , CmpNat, natVal', someNatVal )
import GHC.Exts ( Proxy#, proxy# )
import Unsafe.Coerce (unsafeCoerce)

type Nat16 :: Nat -> Constraint
type Nat16 n = (KnownNat n, CmpNat n 65536 ~ 'LT)

data SomeNat16 where
    SomeNat16 :: forall (n :: Nat). Nat16 n => Proxy n -> SomeNat16

-- | Convert 16-bit type-level natural to corresponding RRTYPE.
natToWord16 :: forall (n :: Nat). Nat16 n => Word16
natToWord16 = fromIntegral $ natVal' (proxy# :: Proxy# n)

-- | Convert RRTYPE to 16-bit natural @SomeNat@ singleton.
wordToNat16 :: Word16 -> SomeNat16
wordToNat16 w = case someNatVal $ fromIntegral w of
    (SomeNat (_ :: Proxy n)) -> case unsafeCoerce Refl :: (CmpNat n 65536 :~: 'LT) of
        Refl -> SomeNat16 (Proxy @n)
