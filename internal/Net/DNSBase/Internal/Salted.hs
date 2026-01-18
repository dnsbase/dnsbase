module Net.DNSBase.Internal.Salted
    ( -- * Existentially reified /salt/.
      Salt(.., SaltValue)
    , withSalt
      -- * Newtype wrapper with phantom type-level salt.
    , Salted(..)
    , salted
    , unsalted
    , saltedKVL
    , unsaltedKVL
      -- * 'HM.HashMap' with reified salt and salted keys.
      -- The underlying 'HM.HashMap' can be used via either of the strict or
      -- the lazy interfaces.  The map construction combinators below force only
      -- the keys and not the values.  The underlying 'HashMap' combinators
      -- primitives can be used instead:
      --
      -- > import Data.HashMap.Strict as HM
      -- > ...
      -- > salt = SaltValue 42
      -- > withSalt salt \ p -> SaltedMap p $ HM.empty
      -- > withSalt salt \ p -> SaltedMap p $ HM.singleton (salted k) v
      -- > withSalt salt \ p -> SaltedMap p $ HM.fromList $ saltedKVL [(k, v) | ...]
      --
      -- If the values inserted are already in @WHNF@, the two are equivalent.
      --
    , SaltedMap(..)
    , Reducer
    , Reducer2
    , saltedEmpty
    , saltedSingleton
    , saltedFromList
    , saltedToList
    , saltedAlterF
    , saltedLookup
    , withSaltedMap
    , withSaltedMap2
    )
    where
import qualified Data.HashMap.Lazy as HM
import Data.Hashable (Hashable, hashWithSalt)

import Net.DNSBase.Internal.Util

-----

-- | Existentially encoded reified 'Int' proxy.
data Salt where
    Salt :: forall s (p :: Type -> Type). Reifies s Int => p s -> Salt

instance Eq Salt where
    (SaltValue a) == (SaltValue b) = a == b

instance Show Salt where
    showsPrec d (SaltValue a) = showParen (d > 10) $
        showString "SaltValue"
        . showChar ' '
        . showParen (a < 0) (shows a)

-- | Evaluate an expression that reduces reified salt.
withSalt :: forall (r :: Type). Salt
         -> (forall (s :: Type) (p :: Type -> Type). Reifies s Int => p s -> r)
         -> r
withSalt (Salt p) f = f p
{-# INLINE withSalt #-}

shake :: Salt -> Int
shake s = withSalt s reflect
{-# INLINE shake #-}

-- | Construct or pattern match 'Salt' values.
pattern SaltValue :: Int -> Salt
pattern SaltValue i <- (shake -> i) where SaltValue i = reify i Salt
{-# COMPLETE SaltValue #-}

-----

-- | A @newtype@ with phantom type-level salt.
-- Coercible to and from the named enclosed type.
type role Salted phantom nominal
type Salted :: Type -> Type -> Type
newtype Salted s k = Salted k deriving newtype (Eq, Show)

instance (Reifies s Int, Hashable k) => Hashable (Salted s k) where
    hashWithSalt t k = hashWithSalt (t + reflect (Proxy @s)) (unsalted k)
    {-# INLINE hashWithSalt #-}

-- | Coerce to salted.
salted :: forall s k. k -> Salted s k
salted = coerce
{-# INLINE salted #-}

-- | Coerce from salted.
unsalted :: forall s k. Salted s k -> k
unsalted = coerce
{-# INLINE unsalted #-}

-- | Coerce a (key, value) list to one with salted keys.
saltedKVL :: forall s k (v :: Type). [(k, v)] -> [(Salted s k, v)]
saltedKVL = coerce
{-# INLINE saltedKVL #-}

-- | Coerce a (salted key, value) list to one with plain keys.
unsaltedKVL :: forall s k (v :: Type).  [(Salted s k, v)] -> [(k, v)]
unsaltedKVL = coerce
{-# INLINE unsaltedKVL #-}

-----

-- | Underlying 'HashMap' with salted keys.
type SHM :: Type -> Type -> Type -> Type
type SHM s k v = HM.HashMap (Salted s k) v

-- | Existentially wrapped reified salt and associated 'HM.HashMap'.
-- Map equality ignores the salt.  Two maps are considered equal if they have
-- the same underlying (unsalted) keys and associated values.
--
-- >>> sm = saltedFromList (SaltValue 0) [("foo","bar"), ("abc", "def")]
-- >>> sn = saltedFromList (SaltValue 1) [("foo","bar"), ("abc", "def")]
-- >>> sm == sn
-- True
-- >>> mapM_ print [sm, sn]
-- saltedFromList (SaltValue 0) [("abc","def"),("foo","baz")]
-- saltedFromList (SaltValue 1) [("foo","baz"),("abc","def")]
--
type role SaltedMap nominal representational
type SaltedMap :: Type -> Type -> Type
data SaltedMap k v where
    SaltedMap :: forall s k v (p :: Type -> Type). Reifies s Int
              => p s -> SHM s k v -> SaltedMap k v

instance (Hashable k, Eq v) => Eq (SaltedMap k v) where
    sm1 == sm2 = withSaltedMap2 sm1 sm2 (const (==))

instance (Hashable k, Show k, Show v) => Show (SaltedMap k v) where
    showsPrec d sm = showParen (d > 10) $ withSaltedMap sm \ p hm ->
        showString "saltedFromList"
        . showChar ' '
        . showsPrec 11 (Salt p)
        . showChar ' '
        . showsPrec 11 (HM.toList hm)

-- | Type of reducers of the internal form of a salted map to a value.
type Reducer k v r = forall s (p :: Type -> Type).
    Reifies s Int => p s -> SHM s k v -> r

-- | Access the underlying 'HM.HashMap' after exposing the reified salt.
-- If a modified 'HM.HashMap' is returned, a new 'SaltedMap' may need to
-- be constructed, for example:
--
-- > saltedAlterF :: forall k v f. (Functor f, Hashable k)
-- >              => (Maybe v -> f (Maybe v)) -> k -> f (SaltedMap k v)
-- > saltedAlterF f k sm = withSaltedMap sm \ p hm ->
-- >     (SaltedMap p) <$> HM.alterF f (salted k) hm
--
withSaltedMap :: forall k v r. Hashable k
              => SaltedMap k v -> Reducer k v r -> r
withSaltedMap (SaltedMap p m) f = f p m
{-# INLINE withSaltedMap #-}

-- | Type of reducers of two maps with identical salts plus key and value
-- types.  Some of the underlying "Data.HashMap.Lazy" combinators work with two
-- maps to, for example, create a union, or determine whether one map is a
-- submap of another.
type Reducer2 k v r = forall s (p :: Type -> Type).
    Reifies s Int => p s -> SHM s k v -> SHM s k v -> r

-- | Operate on two salted maps with the same salt, rehashing the second to
-- use the same salt as the first if necessary.
withSaltedMap2 :: forall k v r. Hashable k
               => SaltedMap k v -> SaltedMap k v -> Reducer2 k v r -> r
withSaltedMap2 (SaltedMap (p :: pt s) hm1) (SaltedMap (q :: qt t) hm2) f =
    case reflectEq p q of
        Just Refl -> f p hm1 hm2
        _         -> let kvl2 = unsaltedKVL $ HM.toList hm2
                         hm2' = HM.fromList $ saltedKVL kvl2
                      in f (Proxy @s) hm1 hm2'
{-# INLINE withSaltedMap2 #-}

-- | Construct an empty salted hash table.
saltedEmpty :: forall k v. Hashable k => Salt -> SaltedMap k v
saltedEmpty salt =
    withSalt salt \ p -> SaltedMap p $ HM.empty
{-# INLINE saltedEmpty #-}

-- | Construct a singleton salted hash table.
-- The key is simply coerced, and used as-is.
saltedSingleton :: forall k v. Hashable k => Salt -> k -> v -> SaltedMap k v
saltedSingleton salt k v =
    withSalt salt \ p -> SaltedMap p $ HM.singleton (coerce k) v
{-# INLINE saltedSingleton #-}

-- | Construct a salted hash table from a list of plain key/value pairs.
-- The list is simply coerced, and used as-is.
saltedFromList :: forall k v. Hashable k => Salt -> [(k, v)] -> SaltedMap k v
saltedFromList salt =
    withSalt salt \ p -> SaltedMap p . HM.fromList . coerce
{-# INLINE saltedFromList #-}

-- | Extract list of plain @(key, value)@ pairs from a 'SaltedMap'.
saltedToList :: forall k v. Hashable k => SaltedMap k v -> [(k, v)]
saltedToList sm = withSaltedMap sm \ _ hm -> unsaltedKVL $ HM.toList hm
{-# INLINE saltedToList #-}

-- | Perform a simple map lookup.
saltedLookup :: forall k v. Hashable k
             => k -> SaltedMap k v -> Maybe v
saltedLookup k sm = withSaltedMap sm \ _ m -> HM.lookup (coerce k) m
{-# INLINE saltedLookup #-}

-- | Given a function mapping an old value to an embedding of a new value in a
-- 'Functor' structure, return a modified map in which the specified key takes
-- a new value (or is deleted), with the resulting map embedded in the same
-- sort of structure.  For example, this can both return the current value,
-- and assign a new value (or delete the key).
--
-- >>> :set -XTupleSections
-- >>> sm = saltedFromList (SaltValue 0) [("foo","bar"), ("abc", "def")]
-- >>> print $ saltedAlterF (, Just "baz") "foo" sm
-- (Just "bar",saltedFromList (SaltValue 0) [("abc","def"),("foo","baz")])
--
saltedAlterF :: forall k v f. (Functor f, Hashable k)
             => (Maybe v -> f (Maybe v))
             -> k
             -> SaltedMap k v
             -> f (SaltedMap k v)
saltedAlterF f k sm = withSaltedMap sm \ p m ->
    (SaltedMap p) <$> HM.alterF f (salted k) m
{-# INLINE saltedAlterF #-}
