-- |
-- Module      : Data.Salted.Map
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-style
--
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : experimental
-- Portability : portable
--
-- Salted hashtables based on "Data.HashMap.Strict".
--
module Data.Salted.Map
    ( -- * SaltedMap data type
      SaltedMap(..)
      -- *  Combinators
    , adjust
    , alter
    , alterF
    , compose
    , delete
    , difference
    , differenceWith
    , differenceWithKey
    , disjoint
    , elems
    , empty
    , keys
    , filter
    , filterWithKey
    , findWithDefault
    , foldMapWithKey
    , foldlWithKey
    , foldlWithKey'
    , foldrWithKey
    , foldrWithKey'
    , fromList
    , fromListWith
    , fromListWithKey
    , insert
    , insertWith
    , intersection
    , intersectionWith
    , intersectionWithKey
    , isSubmapOf
    , isSubmapOfBy
    , lookup
    , lookupKey
    , map
    , mapKeys
    , mapMaybe
    , mapMaybeWithKey
    , mapWithKey
    , member
    , null
    , singleton
    , size
    , toList
    , traverseWithKey
    , unionWith
    , unionWithKey
    , update
      -- * Underlying 'HashMap' access.
    , type MapHandler
    , withSaltedMap
    , type MapsHandler
    , withSaltedMaps
      -- * Re-export of "Data.Salted"
    , module Data.Salted

    -- * Overview
    -- $overview
    ) where
import qualified Data.HashMap.Strict as M
import qualified Data.HashMap.Lazy as LM
import qualified Data.List as L
import qualified Data.Foldable as Foldable
import Control.DeepSeq (NFData(..))
import Data.Bifoldable (Bifoldable(..))
import Data.Coerce (coerce)
import Data.Hashable (Hashable(..))
import Data.HashMap.Lazy (HashMap)
import Data.Kind (Type)
import Data.Salted
import Data.Semigroup (Semigroup(..), stimesIdempotentMonoid)
import Prelude hiding (Foldable (..), filter, lookup, map)

----- HashMap with salted keys.

-- | Existentially wrapped reified salt and associated 'HashMap'.  Map equality
-- ignores the salt.  Two maps are considered equal if they have the same
-- underlying (unsalted) keys and associated values.
--
-- >>> m = fromList $ SKVL (toEnum 0) [("foo","bar"),("abc", "def")]
-- >>> n = fromList $ SKVL (toEnum 1) [("abc", "def"),("foo","bar")]
-- >>> m == n
-- True
-- >>> mapM_ print [m, n]
-- fromList (SKVL (SaltValue 0) [("abc","def"),("foo","baz")])
-- fromList (SKVL (SaltValue 1) [("foo","baz"),("abc","def")])
--
-- The underlying 'HashMap' objects implement 'Ord', but that order depends on
-- the hash values of the keys, which is salt-dependent, so no 'Ord' instance
-- is provided for 'SaltedMap'.
--
type role SaltedMap nominal representational
type SaltedMap :: Type -> Type -> Type
data SaltedMap k v where
     SaltedMap :: forall p s k v. Salty p s
               => p s
               -> HashMap (Salted s k) v
               -> SaltedMap k v

-- | \(O(\log n)\) Adjust the value tied to a given key in this map only if it
-- is present.  Otherwise, leave the map alone.
adjust :: forall k v. Hashable k
       => (v -> v) -> k -> SaltedMap k v -> SaltedMap k v
adjust f k (SaltedMap p m) = SaltedMap p $ M.adjust f (Salted k) m
{-# INLINE adjust #-}

-- | \(O(\log n)\) The expression @(alter f k map)@ alters the value at @k@, or
-- absence thereof.
alter :: forall k v. Hashable k
      => (Maybe v -> Maybe v) -> k -> SaltedMap k v -> SaltedMap k v
alter f k (SaltedMap p m) = SaltedMap p $ M.alter f (Salted k) m
{-# INLINE alter #-}

-- | \(O(\log n)\)  The expression (@'alterF' f k map@) alters the value @x@ at
-- @k@, or absence thereof.
--
-- Given a function mapping an old value to an embedding of a new value in a
-- 'Functor' structure, return a modified 'SaltedMap' in which the specified
-- key takes a new value (or is deleted), with the resulting 'SaltedMap'
-- embedded in the same sort of structure.  For example, this can both return
-- the previous value, and assign a new value (or delete the key).
--
-- >>> :set -XTupleSections
-- >>> m = fromList $ SKVL (toEnum 0) [("foo","bar"),("abc", "def")]
-- >>> alterF (, Just "baz") "foo" m
-- (Just "bar",fromList (SKVL (SaltValue 0) [("abc","def"),("foo","baz")]))
--
alterF :: forall k v f. (Functor f, Hashable k)
       => (Maybe v -> f (Maybe v)) -> k -> SaltedMap k v -> f (SaltedMap k v)
alterF f k (SaltedMap p m) = SaltedMap p <$> M.alterF f (Salted k) m
{-# INLINE alterF #-}

-- | Given maps @bc@ and @ab@, relate the keys of @ab@ to the values of @bc@,
-- by using the values of @ab@ as keys for lookups in @bc@.
--
-- No conversions are needed even if the two maps employ different salts.  The
-- resulting map employs the same salt as the second argument.
--
-- Complexity: \(O(n * \log(m))\), where \(m\) is the size of the first
-- argument.
compose :: forall a b c. Hashable b
        => SaltedMap b c -> SaltedMap a b -> SaltedMap a c
compose (SaltedMap _ mb) (SaltedMap pa ma) =
    SaltedMap pa $ M.mapMaybe (\ b -> M.lookup (Salted b) mb) ma
{-# INLINE compose #-}

-- | \(O(\log n)\) Remove the mapping for the specified key from this map if
-- present.
delete :: forall k v. Hashable k
       => k -> SaltedMap k v -> SaltedMap k v
delete k (SaltedMap p m) = SaltedMap p $ LM.delete (Salted k) m
{-# INLINE delete #-}

-- | \(O(n \log m)\) Difference of two maps.
-- Return elements of the first map whose keys don't exist in the second.
--
-- If the two maps employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
difference :: forall k v w. Hashable k
           => SaltedMap k v -> SaltedMap k w -> SaltedMap k v
difference sm1 sm2 = withSaltedMaps sm1 sm2 \ p m1 m2 ->
    SaltedMap p $ LM.difference m1 m2
{-# INLINE difference #-}

-- | \(O(n \log m)\) Difference with a combining function.  When two equal keys
-- are encountered, the combining function is applied to the values of these
-- keys. If it returns 'Nothing', the element is discarded (proper set
-- difference). If it returns ('Just' @y@), the element is updated with a new
-- value @y@.
--
-- If the two maps employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
differenceWith :: forall k v w. Hashable k
               => (v -> w -> Maybe v) -> SaltedMap k v -> SaltedMap k w -> SaltedMap k v
differenceWith f sm1 sm2 = withSaltedMaps sm1 sm2 \ p m1 m2 ->
    SaltedMap p $ LM.differenceWith f m1 m2
{-# INLINE differenceWith #-}

-- | \(O(n \log m)\) Difference with a combining function. When two equal keys
-- are encountered, the combining function is applied to the values of these
-- keys. If it returns 'Nothing', the element is discarded (proper set
-- difference). If it returns ('Just' @y@), the element is updated with a new
-- value @y@.
--
-- If the two maps employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
differenceWithKey :: forall k v w. Hashable k
                  => (k -> v -> w -> Maybe v) -> SaltedMap k v -> SaltedMap k w -> SaltedMap k v
differenceWithKey f sm1 sm2 = withSaltedMaps sm1 sm2 \ p m1 m2 ->
    SaltedMap p $ LM.differenceWithKey (SaltedFunc1 f) m1 m2
{-# INLINE differenceWithKey #-}

-- | \(O(n \log m)\) Check whether the key sets of two maps are disjoint (i.e.,
-- their intersection is empty).
--
-- If the two maps employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
disjoint :: forall k v w. Hashable k
         => SaltedMap k v -> SaltedMap k w -> Bool
disjoint sm1 sm2 = withSaltedMaps sm1 sm2 \ _ m1 m2 -> LM.disjoint m1 m2
{-# INLINE disjoint #-}

-- | \(O(n)\) Return a list of this map's values. The list is produced lazily.
elems :: forall k v. SaltedMap k v -> [v]
elems (SaltedMap _ m) = LM.elems m
{-# INLINE elems #-}

-- | \(O(1)\) Construct an empty 'SaltedMap' that employs the given salt.
empty :: forall k v. Hashable k => Salt -> SaltedMap k v
empty salt = withSalt salt \ p -> SaltedMap p $ LM.empty
{-# INLINE empty #-}

-- | \(O(n)\) Return a list of this map's keys. The list is produced lazily.
keys :: forall k v. SaltedMap k v -> [k]
keys (SaltedMap _ m) = coerce $ LM.keys m
{-# INLINE keys #-}

-- | \(O(n)\) Filter this map by retaining only elements which values satisfy a
-- predicate.
filter :: forall k v. (v -> Bool) -> SaltedMap k v -> SaltedMap k v
filter f (SaltedMap p m) = SaltedMap p $ LM.filter f m
{-# INLINE filter #-}

-- | \(O(n)\) Filter this map by retaining only elements satisfying a
-- predicate.
filterWithKey :: forall k v. (k -> v -> Bool) -> SaltedMap k v -> SaltedMap k v
filterWithKey f (SaltedMap p m) =
    SaltedMap p $ LM.filterWithKey (SaltedFunc1 f) m
{-# INLINE filterWithKey #-}

-- | \(O(\log n)\) Return the value to which the specified key is mapped, or
-- the default value if this map contains no mapping for the key.
findWithDefault :: forall k v. Hashable k
                => v -> k -> SaltedMap k v -> v
findWithDefault v k (SaltedMap _ m) = M.findWithDefault v (Salted k) m
{-# INLINE findWithDefault #-}

-- | \(O(n)\) Reduce the map by applying a function to each element and
-- combining the results with a monoid operation.
foldMapWithKey :: forall k v m. Monoid m
               => (k -> v -> m) -> SaltedMap k v -> m
foldMapWithKey f (SaltedMap _ m) = M.foldMapWithKey (SaltedFunc1 f) m
{-# INLINE foldMapWithKey #-}

-- | \(O(n)\) Reduce this map by applying a binary operator to all elements,
-- using the given starting value (typically the left-identity of the
-- operator).
foldlWithKey :: forall acc k v. (acc -> k -> v -> acc)
             -> acc -> SaltedMap k v -> acc
foldlWithKey f a (SaltedMap _ m) = M.foldlWithKey (SaltedFunc2 f) a m
{-# INLINE foldlWithKey #-}

-- | \(O(n)\) Reduce this map by applying a binary operator to all elements,
-- using the given starting value (typically the left-identity of the
-- operator).  Each application of the operator is evaluated before using the
-- result in the next application.  This function is strict in the starting
-- value.
foldlWithKey' :: forall acc k v. (acc -> k -> v -> acc)
              -> acc -> SaltedMap k v -> acc
foldlWithKey' f a (SaltedMap _ m) = M.foldlWithKey' (SaltedFunc2 f) a m
{-# INLINE foldlWithKey' #-}

-- | \(O(n)\) Reduce this map by applying a binary operator to all elements,
-- using the given starting value (typically the right-identity of the
-- operator).
foldrWithKey :: forall acc k v. (k -> v -> acc -> acc)
             -> acc -> SaltedMap k v -> acc
foldrWithKey f a (SaltedMap _ m) = M.foldrWithKey (SaltedFunc1 f) a m
{-# INLINE foldrWithKey #-}

-- | \(O(n)\) Reduce this map by applying a binary operator to all elements,
-- using the given starting value (typically the right-identity of the
-- operator).  Each application of the operator is evaluated before using the
-- result in the next application.  This function is strict in the starting
-- value.
foldrWithKey' :: forall acc k v. (k -> v -> acc -> acc)
              -> acc -> SaltedMap k v -> acc
foldrWithKey' f a (SaltedMap _ m) = M.foldrWithKey' (SaltedFunc1 f) a m
{-# INLINE foldrWithKey' #-}

-- | \(O(n \log n)\) Construct a 'SaltedMap' from the supplied salt and list of
-- plain key-value pairs.  The list is simply coerced, and used as-is.  If the
-- list contains duplicate mappings, the later mappings take precedence.
fromList :: forall k v. Hashable k => SomeSKVL k v -> SaltedMap k v
fromList (SomeSKVL p kv) = SaltedMap p $ M.fromList kv
{-# INLINE fromList #-}

-- | \(O(n \log n)\) Construct a 'SaltedMap' from the supplied salt and list of
-- plain key-value pairs.  The list is simply coerced, and used as-is.
-- Uses the provided function @f@ to merge duplicate entries with
-- @(f newVal oldVal)@.
fromListWith :: forall k v. Hashable k
             => (v -> v -> v) -> SomeSKVL k v -> SaltedMap k v
fromListWith f (SomeSKVL p kv) = SaltedMap p $ M.fromListWith f kv
{-# INLINE fromListWith #-}

-- | \(O(n \log n)\) Construct a 'SaltedMap' from the supplied salt and list of
-- plain key-value pairs.  The list is simply coerced, and used as-is.
-- Uses the provided function @f@ to merge duplicate entries with
-- @(f key newVal oldVal)@.
fromListWithKey :: forall k v. Hashable k
                => (k -> v -> v -> v) -> SomeSKVL k v -> SaltedMap k v
fromListWithKey f (SomeSKVL p kv) = SaltedMap p $
    M.fromListWithKey (SaltedFunc1 f) kv
{-# INLINE fromListWithKey #-}

-- | \(O(\log n)\) Associate the specified value with the specified key in this
-- map. If this map previously contained a mapping for the key, the old value
-- is replaced.
insert :: forall k v. Hashable k
       => k -> v -> SaltedMap k v -> SaltedMap k v
insert k v (SaltedMap p m) = SaltedMap p $ M.insert (Salted k) v m
{-# INLINE insert #-}

-- | \(O(\log n)\) Associate the value with the key in this map. If this map
-- previously contained a mapping for the key, the old value is replaced by the
-- result of applying the given function to the new and old value.
insertWith :: forall k v. Hashable k
           => (v -> v -> v) -> k -> v -> SaltedMap k v -> SaltedMap k v
insertWith f k v (SaltedMap p m) =
    SaltedMap p $ M.insertWith f (Salted k) v m
{-# INLINE insertWith #-}


-- | \(O(n \log m)\) Intersection of two maps. Return elements of the first map
-- for keys existing in the second.
--
-- If the two maps employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
intersection :: forall k v w. Hashable k
             => SaltedMap k v -> SaltedMap k w -> SaltedMap k v
intersection sm1 sm2 = withSaltedMaps sm1 sm2 \ p m1 m2 ->
    SaltedMap p $ M.intersection m1 m2
{-# INLINE intersection #-}

-- | \(O(n \log m)\) Intersection of two maps. If a key occurs in both maps
-- the provided function is used to combine the values from the two
-- maps.
--
-- If the two maps employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
intersectionWith :: forall k v1 v2 v3. Hashable k
                 => (v1 -> v2 -> v3) -> SaltedMap k v1 -> SaltedMap k v2
                 -> SaltedMap k v3
intersectionWith f sm1 sm2 = withSaltedMaps sm1 sm2 \ p m1 m2 ->
    SaltedMap p $ M.intersectionWith f m1 m2
{-# INLINE intersectionWith #-}

-- | \(O(n \log m)\) Intersection of two maps. If a key occurs in both maps the
-- provided function is used to combine the values from the two maps.
--
-- If the two maps employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
intersectionWithKey :: forall k v1 v2 v3. Hashable k
                    => (k -> v1 -> v2 -> v3) -> SaltedMap k v1 -> SaltedMap k v2
                    -> SaltedMap k v3
intersectionWithKey f sm1 sm2 = withSaltedMaps sm1 sm2 \ p m1 m2 ->
    SaltedMap p $ M.intersectionWithKey (SaltedFunc1 f) m1 m2
{-# INLINE intersectionWithKey #-}

-- | \(O(n \log m)\) Inclusion of maps. The first map is included in the second
-- if its keys are a subset and the corresponding values are equal.
--
-- If the two maps employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
isSubmapOf :: forall k v. (Hashable k, Eq v)
           => SaltedMap k v -> SaltedMap k v -> Bool
isSubmapOf sm1 sm2 = withSaltedMaps sm1 sm2 \ _ m1 m2 ->
    M.isSubmapOf m1 m2
{-# INLINE isSubmapOf #-}

-- | \(O(n \log m)\) Inclusion of maps with value comparison. The first map is
-- included the second map if its keys are a subset and if the comparison
-- function is true for the corresponding values.
--
-- If the two maps employ different salts the smaller is first converted to the
-- same salt as the larger, raising the cost accordingly.
isSubmapOfBy :: forall k v1 v2. Hashable k
             => (v1 -> v2 -> Bool) -> SaltedMap k v1 -> SaltedMap k v2 -> Bool
isSubmapOfBy f sm1 sm2 = withSaltedMaps sm1 sm2 \ _ m1 m2 ->
    M.isSubmapOfBy f m1 m2
{-# INLINE isSubmapOfBy #-}

-- | \(O(\log n)\) Return the value to which the specified key is mapped, or
-- 'Nothing' if this map contains no mapping for the key.
lookup :: forall k v. Hashable k => k -> SaltedMap k v -> Maybe v
lookup k (SaltedMap _ m) = M.lookup (Salted k) m
{-# INLINE lookup #-}

-- | \(O(\log n)\) For a given key, return the equal key stored in the map, if
-- present, otherwise return 'Nothing'.
--
-- This function can be used for /interning/, i.e. to reduce memory usage.
lookupKey :: forall k v. Hashable k => k -> SaltedMap k v -> Maybe k
lookupKey k (SaltedMap _ m) = coerce $ M.lookupKey (Salted k) m
{-# INLINE lookupKey #-}

-- | \(O(n)\) Transform this map by applying a function to every value.
map :: forall k v w. (v -> w) -> SaltedMap k v -> SaltedMap k w
map f (SaltedMap p m) = SaltedMap p $ M.map f m
{-# INLINE  map #-}

-- | \(O(n)\).
-- @'mapKeys' f s@ is the map obtained by applying @f@ to each key of @s@.
--
-- The size of the result may be smaller if @f@ maps two or more distinct
-- keys to the same new key. In this case there is no guarantee which of the
-- associated values is chosen for the conflicting key.
mapKeys :: forall k1 k2 v. Hashable k2 => (k1 -> k2)
        -> SaltedMap k1 v -> SaltedMap k2 v
mapKeys f (SaltedMap p m) = SaltedMap p $ M.mapKeys (SaltedEndo f) m
{-# INLINE mapKeys #-}

-- | \(O(n)\) Transform this map by applying a function to every value and
-- retaining only some of them.
mapMaybe :: forall k v w. (v -> Maybe w)
         -> SaltedMap k v -> SaltedMap k w
mapMaybe f (SaltedMap p m) = SaltedMap p $ M.mapMaybe f m
{-# INLINE mapMaybe #-}

-- | \(O(n)\) Transform this map by applying a function to every value and
-- retaining only some of them.
mapMaybeWithKey :: forall k v w. (k -> v -> Maybe w)
                -> SaltedMap k v -> SaltedMap k w
mapMaybeWithKey f (SaltedMap p m) =
    SaltedMap p $ M.mapMaybeWithKey (SaltedFunc1 f) m
{-# INLINE mapMaybeWithKey #-}

-- | \(O(n)\) Transform this map by applying a function to every value.
mapWithKey :: forall k v w. (k -> v -> w)
           -> SaltedMap k v -> SaltedMap k w
mapWithKey f (SaltedMap p m) =
    SaltedMap p $ M.mapWithKey (SaltedFunc1 f) m
{-# INLINE  mapWithKey #-}

-- | \(O(\log n)\) Return 'True' if the specified key is present in the map,
-- 'False' otherwise.
member :: forall k v. Hashable k
       => k -> SaltedMap k v -> Bool
member k (SaltedMap _ m) = M.member (Salted k) m
{-# INLINE member #-}

-- | \(O(1)\) Return 'True' if this map is empty, 'False' otherwise.
null :: forall k v. SaltedMap k v -> Bool
null (SaltedMap _ m) = M.null m
{-# INLINE null #-}

-- | -- | \(O(1)\) Construct a 'Salted' with the given salt and a single element.
-- The key is simply coerced, and used as-is.
singleton :: forall k v. Hashable k => Salt -> k -> v -> SaltedMap k v
singleton salt k v = withSalt salt \ p -> SaltedMap p $ M.singleton (coerce k) v
{-# INLINE singleton #-}

-- | \(O(n)\) Return the number of key-value mappings in this map.
size :: forall k v. SaltedMap k v -> Int
size (SaltedMap _ m) = M.size m
{-# INLINE size #-}

-- | \(O(n)\) Extract salt value and list of plain @(key, value)@ pairs from a
-- 'SaltedMap'.
--
-- The list is produced lazily. The order of its elements is unspecified, and
-- it may change from version to version of either this package or of
-- @hashable@.
toList :: forall k v. SaltedMap k v -> SomeSKVL k v
toList (SaltedMap p m) = SomeSKVL p (M.toList m)
{-# INLINE toList #-}

-- | \(O(n)\) Perform an 'Applicative' action for each key-value pair
-- in a 'SaltedMap' and produce a 'SaltedMap' of all the results.
--
-- Note: the order in which the actions occur is unspecified. In particular,
-- when the map contains hash collisions, the order in which the actions
-- associated with the keys involved will depend in an unspecified way on
-- their insertion order.
traverseWithKey :: forall f k v w. Applicative f => (k -> v -> f w)
                -> SaltedMap k v -> f (SaltedMap k w)
traverseWithKey f (SaltedMap p m) =
    SaltedMap p <$> M.traverseWithKey (SaltedFunc1 f) m
{-# INLINE traverseWithKey #-}

-- | \(O(n+m)\) The union of two maps.  If a key occurs in both maps, the
-- provided function (first argument) will be used to compute the result.
--
-- If the two maps employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
unionWith :: forall k v. Hashable k => (v -> v -> v)
          -> SaltedMap k v -> SaltedMap k v -> SaltedMap k v
unionWith f sm1 sm2
    -- Avoid inherting the default salt from 'mempty'
    | null sm1 = sm2
    | null sm2 = sm1
    | otherwise      = withSaltedMaps sm1 sm2 \ p m1 m2 ->
        SaltedMap p $ M.unionWith f m1 m2
{-# INLINE unionWith #-}

-- | \(O(n+m)\) The union of two maps.  If a key occurs in both maps,
-- the provided function (first argument) will be used to compute the
-- result.
--
-- If the two maps employ different salts, the smaller is first rehashed to
-- match the salt of the larger, raising the complexity accordingly.
unionWithKey :: forall k v. Hashable k => (k -> v -> v -> v)
             -> SaltedMap k v -> SaltedMap k v -> SaltedMap k v
unionWithKey f sm1 sm2
    -- Avoid inherting the default salt from 'mempty'
    | null sm1  = sm2
    | null sm2  = sm1
    | otherwise = withSaltedMaps sm1 sm2 \ p m1 m2 ->
        SaltedMap p $ M.unionWithKey (SaltedFunc1 f) m1 m2
{-# INLINE unionWithKey #-}

-- | \(O(\log n)\)  The expression @('update' f k map)@ updates the value @x@
-- at @k@ (if it is in the map). If @(f x)@ is 'Nothing', the element is
-- deleted.  If it is @('Just' y)@, the key @k@ is bound to the new value @y@.
update :: forall k v. Hashable k => (v -> Maybe v)
       -> k -> SaltedMap k v -> SaltedMap k v
update f k (SaltedMap p m) = SaltedMap p $ M.update f (Salted k) m
{-# INLINE update #-}

-- | Process a @('HashMap' ('Salted' s k) v)@ input to an output @r@
type MapHandler k v r = forall p s. Salty p s
                      => p s
                      -> HashMap (Salted s k) v -> r

-- | Apply a function taking a reified salt value, and a 'HashMap'
-- object with that (salted) key type to a 'SaltedMap'.
withSaltedMap :: forall k v r.
              SaltedMap k v -> MapHandler k v r -> r
withSaltedMap (SaltedMap p m) f = f p m
{-# INLINE withSaltedMap #-}

-- | Process two @('HashMap' ('Salted' s k) v)@ inputs to an output @r@
type MapsHandler k v w r = forall p s. Salty p s
                         => p s ->
                         HashMap (Salted s k) v ->
                         HashMap (Salted s k) w -> r

-- | Apply a function taking a reified salt and two 'HashMap' objects with that
-- same (salted) key type to the arguments, rehashing the smaller to use the same
-- salt as the larger if necessary.
withSaltedMaps :: forall k v w r. Hashable k
               => SaltedMap k v
               -> SaltedMap k w
               -> MapsHandler k v w r -> r
withSaltedMaps (SaltedMap p1 m1) (SaltedMap p2 m2) f =
    case saltyEq p1 p2 of
        Just SameSalt -> f p1 m1 m2
        _ | LM.size m1 >= LM.size m2
             -> let m' = LM.fromList (coerce (LM.toList m2))
                 in f p1 m1 m'
          | otherwise
             -> let m' = LM.fromList (coerce (LM.toList m1))
                 in f p2 m' m2
{-# INLINE withSaltedMaps #-}

----- 'SaltedMap' typeclass instances

instance (Hashable k, Eq v) => Eq (SaltedMap k v) where
    sm1 == sm2
        | size sm1 /= size sm2 = False
        | otherwise = withSaltedMaps sm1 sm2 (const (==))

instance (Show k, Show v) => Show (SaltedMap k v) where
    showsPrec d sm = showParen (d > 10) $
        showString "fromList"
        . showChar ' '
        . showsPrec 11 (toList sm)

-- | Less efficient when the two maps don't share a common salt.
instance Hashable k => Semigroup (SaltedMap k v) where
    -- | Union of the two maps.
    --
    -- If the two maps employ different salts, the smaller is first rehashed to
    -- match the salt of the larger, raising the complexity accordingly.
    sm1 <> sm2
        -- Avoid inherting the default salt from 'mempty'
        | null sm1 = sm2
        | null sm2 = sm1
        | otherwise      = withSaltedMaps sm1 sm2 \ p m1 m2 ->
            SaltedMap p $ m1 <> m2
    {-# INLINE (<>) #-}
    stimes = stimesIdempotentMonoid
    {-# INLINE stimes #-}

-- | The 'Monoid''s identity element works well under composition, but is not
-- a good choice for an initially empty map to expand by inserting more values.
-- Its fixed salt value lacks collision resistance given adverserially-chosen
-- keys.
instance Hashable k => Monoid (SaltedMap k v) where
    mempty = empty (toEnum 0)
    {-# INLINE mempty #-}

instance Functor (SaltedMap k) where
    fmap f (SaltedMap p m) = SaltedMap p $ fmap f m

instance Foldable.Foldable (SaltedMap k) where
    foldMap f (SaltedMap _ m) = Foldable.foldMap f m
    {-# INLINE foldMap #-}
    foldr f z (SaltedMap _ m) = Foldable.foldr f z m
    {-# INLINE foldr #-}
    foldr' f z (SaltedMap _ m) = Foldable.foldr' f z m
    {-# INLINE foldr' #-}
    foldl f z (SaltedMap _ m) = Foldable.foldl f z m
    {-# INLINE foldl #-}
    foldl' f z (SaltedMap _ m) = Foldable.foldl' f z m
    {-# INLINE foldl' #-}
    null (SaltedMap _ m) = Foldable.null m
    {-# INLINE null #-}
    length (SaltedMap _ m) = Foldable.length m
    {-# INLINE length #-}

instance Bifoldable SaltedMap where
    bifoldMap f g (SaltedMap _ m) = bifoldMap (coerce f) g m
    {-# INLINE bifoldMap #-}
    bifoldr f g z (SaltedMap _ m) = bifoldr (coerce f) g z m
    {-# INLINE bifoldr #-}
    bifoldl f g z (SaltedMap _ m) = bifoldl (coerce f) g z m
    {-# INLINE bifoldl #-}

instance Traversable (SaltedMap k) where
    traverse f (SaltedMap p m) = SaltedMap p <$> (traverse f m)
    {-# INLINE traverse #-}

instance (NFData k, NFData v) => NFData (SaltedMap k v) where
    rnf (SaltedMap p m) = case fromEnum (Salt p) of _ -> rnf m

-- $overview
--
-- #overview#
-- Salted hashtables based on "Data.HashMap.Strict".
-- Along with the underlying 'HashMap' these enclose a proxy for a reified salt
-- value used to modify the hashing of the keys.
--
-- The runtime representation of the keys remains unchanged, the keys @k@ are
-- coerced to the @('Salted' s k)@ @newtype@ in which @s@ is a phantom parameter
-- that reifies the salt value.
--
-- Accordingly, the table type is then @'HashMap' ('Salted' s k) v@, rather than
-- @'HashMap' k v@.  The table's reified salt is captured via a GADT:
--
-- > data SaltedMap k v where
-- >      SaltedMap :: forall p s. Salty p s => p s
-- >                -> HashMap (Salted s k) v
-- >                -> SaltedMap k v
--
-- The 'SomeSKVL' datatype is the input type of this module's 'fromList' and
-- the output type of its 'toList' combinators.  Note that the @Foldable k@
-- instance provides a different @toList@ that outputs just the values, without
-- the keys.  The order of the key-value pairs in the the output of 'toList'
-- depends on the chosen salt, and is subject to change across releases of this
-- or the @hashable@ packages.
--
-- The underlying 'HashMap' can be used via either of its strict or lazy
-- interfaces.  These differ only in whether values are forced to @WHNF@ before
-- being stored in the map.  The combinators in this module generally use the
-- strict API.  When the values to be inserted are already in @WHNF@, the two
-- APIs are equivalent.  When the lazy API is preferred, the 'LM.HashMap'
-- combinators can be used instead:
--
-- > import Data.HashMap.Lazy as LM
-- > salt = SaltValue 42
-- > a = withSalt salt \ p ->
-- >     SaltedMap p $ LM.singleton (Salted "abc") "def"
-- > b = withSalt (toEnum 0) \ p ->
-- >     SaltedMap p $ LM.fromList $ SaltedKVL [("foo","bar")]
-- > c = withSaltedMaps a b \ p m1 m2 ->
-- >     SaltedMap p $ LM.union m1 m2
-- > f m_old = (m_old, Just "baz")
-- > case c of
-- >     SaltedMap p m -> SaltedMap p <$> LM.alterF f (Salted "foo") m
-- @
-- (Just "bar",fromList (SKVL (SaltValue 42) [("abc","def"),("foo","baz")]))
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
-- 'Monoid'.  so, though present as separate functions in the underlying
-- 'HashMap' API, they are not separately implemented here.
