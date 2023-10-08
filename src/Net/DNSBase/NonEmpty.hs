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
