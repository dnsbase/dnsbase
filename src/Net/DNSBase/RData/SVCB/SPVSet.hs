module Net.DNSBase.RData.SVCB.SPVSet
    ( SPVSet(SPVMap)
    , spvLookup
    , spvSetFromMonoList
    ) where

import qualified Data.IntMap.Strict as IM
import GHC.IsList(IsList(..))

import Net.DNSBase.Internal.Util

import Net.DNSBase.RData.SVCB.SVCParamValue

-- | The 'Monoid' instance provides an /empty/ map.
--
newtype SPVSet = SPVSet (IM.IntMap SVCParamValue)
    deriving (Eq, Semigroup, Monoid)

instance Show SPVSet where
    showsPrec p (toList -> pvs) = showsP p $
        showString "fromList @SPVSet " . shows' pvs

-- | One-sided pattern exposing the internal map from
-- 'Int' keys to generic 'SVCParameterValue' data, the value for any key may or
-- may not be opaque.
--
-- The 'spvLookup' function provides a more convenient interface for /known/
-- keys, returning the decoded structure of the associated type.
--
pattern SPVMap :: IM.IntMap SVCParamValue -> SPVSet
pattern SPVMap m <- SPVSet m

-- | Search for a known parameter by type.  Opaque parameters require an
-- explicit lookup, though their key value may match the requested type.
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

spvSetFromMonoList :: [SVCParamValue] -> SPVSet
spvSetFromMonoList = coerce $ IM.fromDistinctAscList . map kv
  where
    kv !v = let !k = fromIntegral $ serviceParamKey v in (k, v)
