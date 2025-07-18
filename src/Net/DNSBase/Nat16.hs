{-# LANGUAGE ExplicitNamespaces #-}

module Net.DNSBase.Nat16
    ( -- * 16-bit type-level naturals for Opaque RData
      type Nat
    , type Nat16
    , Typeable
    , natToWord16
    , withNat16
    )
    where

import Net.DNSBase.Internal.Nat16
