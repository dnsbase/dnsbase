{-|
Module      : Net.DNSBase.NonEmpty
Description : Non-empty-list interface for collection-shaped RR data
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 'NonEmpty' type from "Data.List.NonEmpty" plus a typeclass
'IsNonEmptyList' modelled on 'GHC.IsList.IsList': types like
'Net.DNSBase.RData.SVCB.SPV_mandatory' that hold a non-empty
collection can derive a conversion through this class without
having to provide the @[a]@-typed 'GHC.IsList.IsList' interface
that would tempt callers into supplying empty lists.
-}

module Net.DNSBase.NonEmpty
    ( IsNonEmptyList(..)
    , NonEmpty(..)
    ) where

import Data.List.NonEmpty (NonEmpty(..))
import Data.Kind (Type)

-- | Structures that can be converted to non-empty lists.  Note that
-- 'toNonEmptyList' and 'fromNonEmptyList' aren't necessarily inverses.
-- The result may, for example, be reordered or deduplicated.
class IsNonEmptyList a where
    type Item1 a      :: Type
    toNonEmptyList   :: a -> NonEmpty (Item1 a)
    fromNonEmptyList :: NonEmpty (Item1 a) -> a

instance IsNonEmptyList (NonEmpty a) where
    type Item1 (NonEmpty a) = a
    toNonEmptyList = id
    fromNonEmptyList = id
