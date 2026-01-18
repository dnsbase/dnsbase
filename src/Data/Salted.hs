-- |
-- Module      : Data.Salted
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-style
--
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : experimental
-- Portability : portable
--
-- Reified salt, salted keys and key value pairs.
--
module Data.Salted
    ( -- * Reified /salt/.
      Salt(.., SaltValue)
    , withSalt
    , Salty
    , SameSalt(..)
    , saltyEq
      -- * Newtype wrapper with phantom type-level /salt/.
    , Salted(.., Salted)
    , pattern SaltedEndo
    , pattern SaltedFunc1
    , pattern SaltedFunc2
      -- * Lists of salted keys.
    , SaltedKL
    , pattern SaltedKL
    , SomeSKL(.., SKL)
      -- * Key-value lists with salted keys.
    , SaltedKVL
    , pattern SaltedKVL
    , SomeSKVL(.., SKVL)
      -- * Overview
      -- $overview
    ) where
import Control.DeepSeq (NFData(..))
import Data.Coerce (coerce)
import Data.Hashable (Hashable(..))
import Data.Kind (Type, Constraint)
import Data.Proxy (Proxy(..))
import Data.Reflection (Reifies, reify, reflect)
import Unsafe.Coerce (unsafeCoerce)

----- The 'Salt' datatype.

-- | For a proxy type-constructor @p@ taking a parameter @s@ require that @s@
-- 'Reifies' an 'Int'.
type Salty :: (Type -> Type) -> Type -> Constraint
type Salty p s = (Reifies s Int)

-- | Salt type equality witness
type SameSalt :: Type -> Type -> Type
data SameSalt s t where
     SameSalt :: forall s. SameSalt s s

-- | Test type equality of reified salts.
saltyEq :: forall p s q t. (Salty p s, Salty q t)
        => p s -> q t -> Maybe (SameSalt s t)
saltyEq (reflect -> a) (reflect -> b)
    | a == b = Just $ unsafeCoerce (SameSalt @s)
    | otherwise = Nothing
{-# INLINE saltyEq #-}

-- | Existentially encoded reified 'Int' proxy.
data Salt where
     Salt :: forall p s. Salty p s => p s -> Salt

-- | Construct or match 'Salt' values.
pattern SaltValue :: Int -> Salt
pattern SaltValue i <- (fromEnum -> i) where
        SaltValue i = toEnum i
{-# COMPLETE SaltValue #-}

-- | Evaluate an expression that reduces reified salt.
withSalt :: forall (r :: Type). Salt
         -> (forall p s. Salty p s => p s -> r) -> r
withSalt (Salt p) f = f p
{-# INLINE withSalt #-}

instance Eq Salt where
    a == b = fromEnum a == fromEnum b

instance Enum Salt where
    toEnum i = reify i Salt
    {-# INLINE toEnum #-}
    fromEnum (Salt p) = reflect p
    {-# INLINE fromEnum #-}

instance Show Salt where
    showsPrec d (SaltValue a) = showParen (d > 10) $
        showString "SaltValue"
        . showChar ' '
        . showParen (a < 0) (shows a)

----- The (Salted s) type constructor.

-- | A @newtype@ with phantom type-level salt.
-- Coercible to and from the named enclosed type.
type role Salted phantom nominal
type Salted :: Type -> Type -> Type
newtype Salted s k = Salted_ k

-- | Coercion between salted and plain keys.
pattern Salted :: k -> Salted s k
pattern Salted k <- (coerce -> k) where
        Salted k = coerce k
{-# COMPLETE Salted #-}

-- | Coercion between plain and salted value endomorphisms.
pattern SaltedEndo :: (k1 -> k2) -> (Salted s k1) -> (Salted s k2)
pattern SaltedEndo f <- (coerce -> f) where
        SaltedEndo f = coerce f

-- | Coercion between functions taking a plain and salted first argument.
-- Potentially useful with 'foldr'.
pattern SaltedFunc1 :: (k -> r) -> Salted s k -> r
pattern SaltedFunc1 f <- (coerce -> f) where
        SaltedFunc1 f = coerce f

-- | Coercion between functions taking a plain and salted second argument.
-- Potentially useful with 'foldl'.
pattern SaltedFunc2 :: (a -> k -> r) -> (a -> Salted s k -> r)
pattern SaltedFunc2 f <- (coerce -> f) where
        SaltedFunc2 f = coerce f

deriving newtype instance Eq k => Eq (Salted s k)
deriving newtype instance Ord k => Ord (Salted s k)
deriving newtype instance Show k => Show (Salted s k)
deriving newtype instance NFData k => NFData (Salted s k)
instance (Reifies s Int, Hashable k) => Hashable (Salted s k) where
    hashWithSalt t (Salted k) = hashWithSalt (t + reflect (Proxy @s)) k
    {-# INLINE hashWithSalt #-}
    hash (Salted k) = hashWithSalt (reflect (Proxy @s)) k
    {-# INLINE hash #-}

----- Lists of salted keys.

-- | A list of 'Salted' keys.
type SaltedKL :: Type -> Type -> Type
type SaltedKL s k = [Salted s k]

-- | Coercion between lists of plain and salted keys.
pattern SaltedKL :: [k] -> SaltedKL s k
pattern SaltedKL ks <- (coerce -> ks) where
        SaltedKL ks = coerce ks

-- | Existential wrapper for lists of salted keys.
type role SomeSKL nominal
type SomeSKL :: Type -> Type
data SomeSKL k where
     SomeSKL :: forall p s k. Salty p s
             => p s -> SaltedKL s k -> SomeSKL k

-- | Pack or unpack a 'SomeSKL' to/from a 'Salt' with a corresponding plain
-- list of keys.  The list itself is simply coerced.
pattern SKL :: Salt -> [k] -> SomeSKL k
pattern SKL s kl <- (unskl -> (s, kl)) where
        SKL (Salt p) kl = SomeSKL p (coerce kl)
{-# COMPLETE SKL #-}

unskl :: SomeSKL k -> (Salt, [k])
unskl (SomeSKL p kl) = (Salt p, coerce kl)

instance Show k => Show (SomeSKL k) where
    showsPrec d (SKL salt kl) = showParen (d > 10) $
        showString "SKL"
        . showChar ' '
        . showsPrec 11 salt
        . showChar ' '
        . showsPrec 11 kl

----- Key/Value lists with salted keys.

-- | A key-value list with 'Salted' keys.
type SaltedKVL :: Type -> Type -> Type -> Type
type SaltedKVL s k v = [(Salted s k, v)]

-- | Coercion betwen plain and salted key-value lists.
pattern SaltedKVL :: [(k, v)] -> SaltedKVL s k v
pattern SaltedKVL skvl <- (coerce -> skvl) where
        SaltedKVL skvl = coerce skvl
{-# COMPLETE SaltedKVL #-}

-- | Existential wrapper for salted key-value lists.
type role SomeSKVL nominal representational
type SomeSKVL :: Type -> Type -> Type
data SomeSKVL k v where
     SomeSKVL :: forall p s k v. Salty p s
              => p s -> SaltedKVL s k v -> SomeSKVL k v

-- | Pack or unpack a 'SomeSKVL' to/from a 'Salt' with a corresponding plain
-- key-value list.  The list itself is simply coerced.
pattern SKVL :: Salt -> [(k, v)] -> SomeSKVL k v
pattern SKVL s kvl <- (unskvl -> (s, kvl)) where
        SKVL (Salt p) kvl = SomeSKVL p (coerce kvl)
{-# COMPLETE SKVL #-}

-- Helper function for view pattern.
unskvl :: SomeSKVL k v -> (Salt, [(k, v)])
unskvl (SomeSKVL p (SaltedKVL kvl)) = (Salt p, kvl)

instance (Show k, Show v) => Show (SomeSKVL k v) where
    showsPrec d (SKVL salt kvl) = showParen (d > 10) $
        showString "SKVL"
        . showChar ' '
        . showsPrec 11 salt
        . showChar ' '
        . showsPrec 11 kvl

-- $overview
--
-- #overview#
-- This module uses "Data.Reflection" to support tagging 'Hashable' objects of
-- type @k@ with a phantom type-level /salt/ parameter @s@, yielding objects of
-- type @'Salted' s k@.
--
-- The 'Salted' newtype augments an existing datatype with a phantom reified
-- salt parameter, making it possible to define a custom 'Hashable' instance,
-- that incorporates the reified salt value into the hash result.  The 'Salted'
-- pattern synonym implements coercions to and from the underlying value.
--
-- > type role Salted phantom nominal
-- > newtype Salted s k = Salted_ k
-- > pattern Salted :: k -> Salted s k
-- > instance (Reifies s Int, Hashable k) => Hashable (Salted s k) where
-- >     hashWithSalt t (Salted k) = hashWithSalt (t + reflect (Proxy @s)) k
-- >     hash (Salted k) = hashWithSalt (reflect (Proxy @s)) k
--
-- Because 'Salted' is a @newtype@, the runtime representation remains
-- unchanged a data of type @k@ is simply coercible to @'Salted' s k@, the
-- 'Salted' pattern synonym can be used to perform the coercion in either
-- direction.
--
-- A convenience type alias 'Salty' is used to specialise the kind of its first
-- parameter @p@ to be @Type -> Type@ and to constrain its second parameter @s@
-- to reify an 'Int'.  The @p@ parameter is expected to be a /proxy/ type,
-- taking @s@ as a phantom type parameter.
--
-- > type Salty :: (Type -> Type) -> Type -> Constraint
-- > type Salty p s = (Reifies s Int)
--
-- This is used in the definitions of the below of salted key lists,
-- and salted key-value lists:
--
-- > type SaltedKL s k = [Salted s k]
-- > pattern SaltedKL :: [k] -> SaltedKL s k
-- >
-- > type role SomeSKL nominal
-- > type SomeSKL :: Type -> Type
-- > data SomeSKL k where
-- >      SomeSKL :: forall p s k. Salty p s
-- >              => p s -> SaltedKL s k -> SomeSKL k
-- > pattern SKL :: Salt -> [k] -> SomeSKL k
--
-- > pattern SaltedKVL :: [(k, v)] -> SaltedKVL s k V
-- >
-- > type role SomeSKVL nominal representational
-- > type SomeSKVL :: Type -> Type -> Type
-- > type SaltedKVL s k v = [(Salted s k, v)]
-- > data SomeSKVL k v where
-- >      SomeSKVL :: forall p s k v. Salty p s
-- >               => p s -> SaltedKVL s k v -> SomeSKL k v
-- > pattern SKVL :: Salt -> [(k, v)] -> SomeSKVL k v
--
-- The example below demonstrates salt-dependent hashing of a list,
-- the underlying list is simpy coerced to a list of salted values,
-- no copying involved:
--
-- >>> import Data.Functor((<&>))
-- >>> kl = [0..1] :: [Int]
-- >>> skl s = SKL (SaltValue s) kl
-- >>> kl <&> \s -> case skl s of { SomeSKL _ l -> map hash l }
-- [[0,-2296964322683963754],[-5451962507482445012,4556620595101080342]]
--
-- Finally, the 'SameSalt' datatype witnesses that two proxies for reified salt
-- values represent the same type (same underlying salt value):
--
-- > data SameSalt s t where
-- >      SameSalt :: forall s. SameSalt s s
--
-- This can be tested with the 'saltyEq' combinator.
--
-- > saltyEq :: forall p s q t. (Salty p s, Salty q t)
-- >         => p s -> q t -> Maybe (SameSalt s t)
