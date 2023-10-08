{-# LANGUAGE ExplicitNamespaces #-}
module Net.DNSBase.Nat16
    ( -- * 16-bit type-level naturals for Opaque RData
      type Nat
    , type Nat16
    , SomeNat16(..)
    , Typeable
    , natToWord16
    , wordToNat16
    )
    where

import Net.DNSBase.Internal.Nat16
