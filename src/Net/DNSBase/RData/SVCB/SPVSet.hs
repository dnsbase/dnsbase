{-|
Module      : Net.DNSBase.RData.SVCB.SPVSet
Description : Indexed collection of SVCB service-parameter values
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The collection of service parameters carried in a single
@SVCB@ or @HTTPS@ record, keyed by 'Net.DNSBase.RData.SVCB.SVCParamKey' (one value
per key code, per RFC 9460).  Construction is via the 'IsList'
instance — @fromList [SVCParamValue p1, ...]@; enumeration via
'toList' returns the parameters in ascending key order, which
is also the canonical on-the-wire order.

Each key code is associated with a specific 'KnownSVCParamValue'
type; the values are held inside the existential 'SVCParamValue'
wrapper so a single set can mix heterogeneous parameter types.
'spvLookup' takes the parameter /type/ as a type application
and returns the typed value when the matching key is present:

> ghci> import qualified GHC.IsList as IL (fromList)
> ghci> spvset = IL.fromList @SPVSet [SVCParamValue (SPV_PORT 80), SVCParamValue SPV_NDALPN]
> ghci> spvset
> fromList @SPVSet [SVCParamValue SPV_NDALPN,SVCParamValue 80]
> ghci> spvLookup @SPV_ndalpn spvset
> Just SPV_NDALPN

The type application can be elided when a pattern match
constrains the result type:

> ghci> case spvLookup spvset of { Just (SPV_PORT p) -> p; _ -> 0 }
> 80
-}

module Net.DNSBase.RData.SVCB.SPVSet
    ( SPVSet(SPVMap)
    , spvLookup
    , spvSetFromMonoList
    ) where

import qualified Data.IntMap.Strict as IM
import GHC.IsList(IsList(..))

import Net.DNSBase.Internal.Util

import Net.DNSBase.Present
import Net.DNSBase.RData.SVCB.SVCParamValue

-- | The set of service parameters in an @SVCB@ or @HTTPS@ record,
-- with at most one value per 'Net.DNSBase.RData.SVCB.SVCParamKey'.  The 'Monoid'
-- instance provides the empty set; the 'Semigroup' instance is
-- left-biased on key collisions.
newtype SPVSet = SPVSet (IM.IntMap SVCParamValue)
    deriving (Eq, Semigroup, Monoid)

instance Show SPVSet where
    showsPrec p (toList -> pvs) = showsP p $
        showString "fromList @SPVSet " . shows' pvs

instance Presentable SPVSet where
    present vs k = case toList vs of
        v:rest -> present v $ foldr presentSp k rest
        []     -> k

-- | One-sided pattern that exposes the underlying 'IM.IntMap' for
-- traversal or low-level inspection.  The values are kept in the
-- existential 'SVCParamValue' wrapper, so any concrete parameter
-- may be either typed (a 'KnownSVCParamValue' instance) or
-- 'Net.DNSBase.RData.SVCB.OpaqueSPV'.  For typed lookups by parameter type use
-- 'spvLookup' instead.
pattern SPVMap :: IM.IntMap SVCParamValue -- ^ Values as an 'IM.IntMap'
               -> SPVSet
pattern SPVMap m <- SPVSet m

-- | Look up the parameter at the key associated with type @a@,
-- returning a 'Just' only when the stored value really is of type
-- @a@.  A value of the same key code but held as 'Net.DNSBase.RData.SVCB.OpaqueSPV'
-- (because the typed instance was not registered when the record
-- was decoded) does /not/ match — opaque values must be
-- retrieved through 'SPVMap'.
spvLookup :: forall a. KnownSVCParamValue a
          => SPVSet -> Maybe a
spvLookup = (>>= fromSPV @a) . IM.lookup key . coerce
  where
    key = fromIntegral $ spvKey a

-- | Construction is via 'fromList', and enumeration is via 'toList'.
instance IsList SPVSet where
    type Item SPVSet = SVCParamValue

    -- | Construct a parameter Map from an unordered list.
    fromList vs =
        coerce $ IM.fromList
               [ (key, v) | v <- vs , let key = fromIntegral $ serviceParamKey v ]

    -- | Return the map as a list in ascending parameter order.
    toList = IM.elems . coerce

-- | Build an 'SPVSet' from a list of 'SVCParamValue's whose keys
-- are in /strict monotone-increasing/ order (so also no
-- duplicates) — the precondition imposed by the underlying
-- 'IM.fromDistinctAscList' used to build the set.  The \"Mono\"
-- is intended as a reminder of the precondition.
--
-- Used internally by the wire-form decoder, which validates
-- ascending keys during parsing; application code that cannot
-- guarantee the precondition should use 'fromList' from the
-- 'IsList' instance instead.
spvSetFromMonoList :: [SVCParamValue] -> SPVSet
spvSetFromMonoList = coerce $ IM.fromDistinctAscList . map kv
  where
    kv !v = let !k = fromIntegral $ serviceParamKey v in (k, v)
