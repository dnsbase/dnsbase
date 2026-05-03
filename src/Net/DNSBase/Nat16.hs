{-|
Module      : Net.DNSBase.Nat16
Description : 16-bit type-level naturals indexing opaque RData
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

A 16-bit-constrained variant of 'Nat': the 'Nat16' constraint
carries enough type-level evidence to retrieve the numeric
codepoint at runtime via 'natToWord16'.  Used to index the
fallback 'Net.DNSBase.RData.OpaqueRData' /
'Net.DNSBase.EDNS.Option.OpaqueOption' /
'Net.DNSBase.RData.SVCB.OpaqueSPV' carriers
so that values for different RR / option / SVCB-parameter
codepoints inhabit distinct types even though they share a
single underlying representation.  'withNat16' brings a runtime
'Data.Word.Word16' value into scope as a 'Nat16'-instantiated type
variable.
-}
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
