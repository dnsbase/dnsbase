-- |
-- Module      : Data.Salted.Set
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-style
--
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : experimental
-- Portability : portable
--
-- Salted hash sets based on "Data.HashSet".
--
module Data.Salted.Set
    (
      -- * 'HashSet' with reified salt and salted keys.
      --
      -- The functions that combine two input sets may, when the salt values
      -- are different, need to convert one of them to use the same salt as the
      -- other.  This can raise the cost of the operation relative to what it
      -- would be, had the two sets used the same salt value.  If combining
      -- sets is on the critical path in your application, best to use the same
      -- salt value across all the sets that are likely to be combined via
      -- functions in this module.
      --
      SaltedSet(..)
      -- *  Combinators
    , delete
    , difference
    , disjoint
    , empty
    , filter
    , fromList
    , fromMap
    , insert
    , intersection
    , isSubsetOf
    , keysSet
    , lookupElement
    , map
    , null
    , member
    , singleton
    , size
    , toList
    , toMap
      -- * Underlying 'HashSet' access.
    , type SetHandler
    , withSaltedSet
    , type SetsHandler
    , withSaltedSets
      -- * Re-export of "Data.Salted"
    , module Data.Salted

    -- * Overview
    -- $overview
    ) where
import qualified Data.HashSet as S
import qualified Data.HashSet.Internal as S
import qualified Data.List as L
import qualified Data.Foldable as Foldable
import qualified Data.Salted.Map as SM
import Control.DeepSeq (NFData(..))
import Data.Coerce (coerce)
import Data.Hashable (Hashable(..))
import Data.HashSet (HashSet)
import Data.Kind (Type)
import Data.Salted
import Data.Semigroup (Semigroup(..), stimesIdempotentMonoid)
import Prelude hiding (Foldable (..), filter, lookup, map)

----- HashSet with salted keys.

-- | Existentially wrapped reified salt and associated 'HashSet'.  Set
-- equality ignores the salt.  Two sets are considered equal if they have the
-- same underlying (unsalted) keys.  The check is more expensive if, when have
-- the same size, they  employ distinct salts, because then the second set
-- needs to be rehashed to use the same salt as the first.
--
-- >>> m = fromList $ SKL (toEnum 0) ["foo","abc"]
-- >>> n = fromList $ SKL (toEnum 1) ["abc","foo"]
-- >>> m == n
-- True
-- >>> mapM_ print [m, n]
-- fromList (SKL (SaltValue 0) ["abc","foo"])
-- fromList (SKL (SaltValue 1) ["foo","abc"])
--
-- The underlying 'HashSet' objects implement 'Ord', but that order depends on
-- the hash values of the keys, which is salt-dependent, so no 'Ord' instance
-- is provided for 'SaltedSet'.
--
type role SaltedSet nominal
type SaltedSet :: Type -> Type
data SaltedSet k where
     SaltedSet :: forall p s k. Salty p s
               => p s
               -> HashSet (Salted s k)
               -> SaltedSet k

-- | \(O(\log n)\) Remove the specified key from this set if present.
delete :: forall k. Hashable k => k -> SaltedSet k -> SaltedSet k
delete k (SaltedSet p a) = SaltedSet p $ S.delete (Salted k) a
{-# INLINE delete #-}

-- | \(O(n \log m)\) Difference of two sets. Return a set with keys present
-- only in first set.
--
-- If the two sets employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
difference :: forall k. Hashable k => SaltedSet k -> SaltedSet k -> SaltedSet k
difference a b = withSaltedSets a b \ p s1 s2 ->
    SaltedSet p $ S.difference s1 s2
{-# INLINE difference #-}

-- | \(O(n \log m)\) Check whether two sets are disjoint (i.e., their
-- intersection is empty).
disjoint :: forall k. Hashable k => SaltedSet k -> SaltedSet k -> Bool
disjoint a b = withSaltedSets a b \ _ s1 s2 -> S.disjoint s1 s2
{-# INLINE disjoint #-}

-- | \(O(1)\) Construct an empty set with the given salt.
empty :: forall k. Salt -> SaltedSet k
empty salt = withSalt salt \ p -> SaltedSet p $ S.empty
{-# INLINE empty #-}

-- | \(O(n)\) Filter this set by retaining only keys satisfying a predicate.
filter :: forall k. Hashable k => (k -> Bool) -> SaltedSet k -> SaltedSet k
filter f (SaltedSet p a) = SaltedSet p $ S.filter (SaltedFunc1 f) a
{-# INLINE filter #-}

-- | \(O(n \log n)\) Construct a set from a given salt and list of keys.
fromList :: forall k. Hashable k => SomeSKL k -> SaltedSet k
fromList (SomeSKL p kl) = SaltedSet p $ S.fromList (coerce kl)
{-# INLINE fromList #-}

-- | \(O(1)\) Convert from the equivalent 'SaltedMap' with @()@ values.
fromMap :: forall k. SM.SaltedMap k () -> SaltedSet k
fromMap (SM.SaltedMap p m) = SaltedSet p $ S.fromMap m
{-# INLINE fromMap #-}

-- | \(O(\log n)\) Add the specified key to this set.
insert :: forall k. Hashable k => k -> SaltedSet k -> SaltedSet k
insert k (SaltedSet p a) = SaltedSet p $ S.insert (Salted k) a
{-# INLINE insert #-}

-- | \(O(n \log m)\) Intersection of two sets. Return keys present in both the
-- first set and the second.
intersection :: forall k. Hashable k => SaltedSet k -> SaltedSet k -> SaltedSet k
intersection a b = withSaltedSets a b \ p s1 s2 ->
    SaltedSet p $ S.intersection s1 s2
{-# INLINE intersection #-}

-- | \(O(n \log m)\) Test whether the first set is included in the second.
--
-- If the two sets employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
isSubsetOf :: forall k. Hashable k => SaltedSet k -> SaltedSet k -> Bool
isSubsetOf a b = withSaltedSets a b \ _ s1 s2 -> S.isSubsetOf s1 s2
{-# INLINE isSubsetOf #-}

-- | \(O(n)\) Produce a 'SaltedSet' of all the keys in the given 'SaltedMap'.
keysSet :: forall k v. SM.SaltedMap k v -> SaltedSet k
keysSet (SM.SaltedMap p m) = SaltedSet p $ S.keysSet m
{-# INLINE keysSet #-}

-- | \(O(\log n)\) For a given input, return the equal key in the set if
-- present, otherwise return 'Nothing'.
lookupElement :: forall k. Hashable k => k -> SaltedSet k -> Maybe k
lookupElement k (SaltedSet _ a) = coerce $ S.lookupElement (Salted k) a
{-# INLINE lookupElement #-}

-- | \(O(n \log n)\) Transform this set by applying a function to every key.
map :: forall a b. Hashable b => (a -> b) -> SaltedSet a -> SaltedSet b
map f (SaltedSet p e) = SaltedSet p $ S.map g e
  where
    g :: (Salted s a) -> (Salted s b)
    g = coerce f
{-# INLINE map #-}

-- | \(O(\log n)\) Return 'True' if the given key is present in this set,
-- 'False' otherwise.
member :: forall k. Hashable k => k -> SaltedSet k -> Bool
member k (SaltedSet _ a) = S.member (Salted k) a
{-# INLINE member #-}

-- | \(O(1)\) Return 'True' if this set is empty, 'False' otherwise.
null :: forall k. SaltedSet k -> Bool
null (SaltedSet _ m) = S.null m
{-# INLINE null #-}

-- | \(O(1)\) Construct a set with the given salt and a single key.
singleton :: forall k. Hashable k => Salt -> k -> SaltedSet k
singleton (Salt p) k = SaltedSet p $ S.singleton (Salted k)
{-# INLINE singleton #-}

-- | \(O(n)\) Return the number of keys in this set.
size :: forall k. SaltedSet k -> Int
size (SaltedSet _ m) = S.size m
{-# INLINE size #-}

-- | \(O(n)\) Return the set's salt together with its list of keys.  The list
-- is produced lazily. The order of its elements is unspecified, and it may
-- change from version to version of either this package or of @hashable@.
toList :: forall k. SaltedSet k -> SomeSKL k
toList (SaltedSet p m) = SomeSKL p (S.toList m)
{-# INLINE toList #-}

-- | \(O(1)\) Convert to the equivalent 'SaltedMap' with @()@ values.
toMap :: forall k. SaltedSet k -> SM.SaltedMap k ()
toMap (SaltedSet p a) = SM.SaltedMap p $ S.toMap a
{-# INLINE toMap #-}

-- | Process a @('HashSet' ('Salted' s k))@ input to an output @r@
type SetHandler k r = forall p s. Salty p s
                    => p s
                    -> HashSet (Salted s k) -> r

-- | Apply a function taking a reified salt value, and a 'HashSet'
-- object with that (salted) key type to a 'SaltedSet'.
withSaltedSet :: forall k r. SaltedSet k -> SetHandler k r -> r
withSaltedSet (SaltedSet p m) f = f p m
{-# INLINE withSaltedSet #-}

-- | Process two @('HashSet' ('Salted' s k))@ inputs to an output @r@
type SetsHandler k r = forall p s. Salty p s
                     => p s
                     -> HashSet (Salted s k)
                     -> HashSet (Salted s k) -> r

-- | Apply a function taking a reified salt and two 'HashSet' objects with that
-- same (salted) key type to the arguments, rehashing the smaller to use the
-- same salt as the larger if necessary.
withSaltedSets :: forall k r. Hashable k
               => SaltedSet k -> SaltedSet k
               -> SetsHandler k r -> r
withSaltedSets (SaltedSet p1 s1) (SaltedSet p2 s2) f =
    case saltyEq p1 p2 of
        Just SameSalt -> f p1 s1 s2
        _ | S.size s1 >= S.size s2
             -> let s' = S.fromList (coerce (S.toList s2))
                 in f p1 s1 s'
          | otherwise
             -> let s' = S.fromList (coerce (S.toList s1))
                 in f p2 s' s2
{-# INLINE withSaltedSets #-}

----- 'SaltedSet' typeclass instances

instance Hashable k => Eq (SaltedSet k) where
    a == b
        | size a /= size b = False
        | otherwise = withSaltedSets a b (const (==))

instance Show k => Show (SaltedSet k) where
    showsPrec d a = showParen (d > 10) $
        showString "fromList"
        . showChar ' '
        . showsPrec 11 (toList a)

-- | Less efficient when the two sets don't share a common salt.
instance Hashable k => Semigroup (SaltedSet k) where
    -- | \(O(n+m)\) Construct a set containing all keys from both sets.
    --
    -- To obtain good performance, the smaller set must be presented as the
    -- first argument.
    a <> b
        -- Avoid inherting the default salt from 'mempty'
        | null a = b
        | null b = a
        | otherwise      = withSaltedSets a b \ p s1 s2 ->
            SaltedSet p $ s1 <> s2
    {-# INLINE (<>) #-}
    stimes = stimesIdempotentMonoid
    {-# INLINE stimes #-}

-- | The 'Monoid''s identity element works well under composition, but is not
-- a good choice for an initially empty set to expand by inserting more keys.
-- Its fixed salt value lacks collision resistance given adverserially-chosen
-- keys.
instance Hashable k => Monoid (SaltedSet k) where
    mempty = empty (toEnum 0)
    {-# INLINE mempty #-}

instance Foldable.Foldable SaltedSet where
    foldMap f (SaltedSet _ m) = Foldable.foldMap (SaltedFunc1 f) m
    {-# INLINE foldMap #-}
    foldr f z (SaltedSet _ m) = Foldable.foldr (SaltedFunc1 f) z m
    {-# INLINE foldr #-}
    foldr' f z (SaltedSet _ m) = Foldable.foldr' (SaltedFunc1 f) z m
    {-# INLINE foldr' #-}
    foldl f z (SaltedSet _ m) = Foldable.foldl (SaltedFunc2 f) z m
    {-# INLINE foldl #-}
    foldl' f z (SaltedSet _ m) = Foldable.foldl' (SaltedFunc2 f) z m
    {-# INLINE foldl' #-}
    null (SaltedSet _ m) = Foldable.null m
    {-# INLINE null #-}
    length (SaltedSet _ m) = Foldable.length m
    {-# INLINE length #-}

instance NFData k => NFData (SaltedSet k) where
    rnf (SaltedSet p m) = case fromEnum (Salt p) of _ -> rnf m

-- $overview
--
-- #overview#
-- Salted hash sets based on "Data.HashSet".
-- Along with the underlying 'HashSet' these enclose a proxy for a reified salt
-- value used to modify the hashing of the keys.
--
-- The runtime representation of the keys remains unchanged, the keys @k@ are
-- coerced to the @('Salted' s k)@ @newtype@ in which @s@ is a phantom parameter
-- that reifies the salt value.
--
-- Accordingly, the set type is then @'HashSet' ('Salted' s k)@, rather than
-- @HashSet k@.  The set's reified salt is captured via a GADT:
--
-- > data SaltedSet k where
-- >      SaltedSet :: forall p s. Salty p s => p s
-- >                -> HashSet (Salted s k)
-- >                -> SaltedSet k
--
-- The 'SomeSKL' datatype is the input type of this module's 'fromList' and the
-- output type of its 'toList' combinators.  Note that the @Foldable k@
-- instance provides a different @toList@ that outputs just the plain
-- (unsalted) keys.  The order of the keys in the the output of 'toList'
-- depends on the chosen salt, and subject to change across releases of this or
-- the @hashable@ packages.
--
-- The underlying 'HashSet' API can be accessed via:
--
-- > import Data.HashSet as HS
-- > salt = SaltValue 42
-- > a = withSalt salt \ p ->
-- >     SaltedSet p $ HS.singleton (Salted "abc")
-- > b = withSalt (toEnum 0) \ p ->
-- >     SaltedSet p $ HS.fromList $ SaltedKL ["foo"]
-- > withSaltedMaps a b \ p m1 m2 ->
-- >     SaltedSet p $ m1 <> m2
-- @
-- fromList (SKL (SaltValue 42) ["abc","foo"])
-- @
--
-- The functions that combine two input maps may, when the salt values
-- are different, need to convert one of them to use the same salt as the
-- other.  This can raise the cost of the operation relative to what it
-- would be, had the two maps used the same salt value.  If combining
-- maps is on the critical path in your application, best to use the same
-- salt value across all the maps that are likely to be combined via
-- functions in this module.
--
-- Some combinators are redundant given corresponding equivalents in associated
-- type classes, e.g., @union@ and @unions@ vs. @mappend@ and @mconcat@ from
-- 'Monoid'.  So, though present as separate functions in the underlying
-- 'HashSet' API, they are not separately implemented here.
