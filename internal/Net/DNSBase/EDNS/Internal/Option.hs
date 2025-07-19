module Net.DNSBase.EDNS.Internal.Option
    ( EdnsOption(..)
    , SomeOption(..)
    , OptEncode
    , OptDecode
    , fromOption
    , monoOption
    , optionCode
    , putOption
    ------
    , OptionCtl
    , optCtlSet
    , optCtlAdd
    , emptyOptionCtl
    , applyOptionCtl
    ) where

import Data.List (sortOn)

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.EDNS.Internal.OptNum
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

-- | Type of methods that encode options to wire form
type OptEncode a = forall s r. (Typeable r, Eq r, Show r) => a -> SPut s r
type OptDecode a = EdnsOption a => Int -> SGet SomeOption

-- | EDNS option class with conversion to/from opaque 'SomeOption' form.
class (Typeable a, Eq a, Show a, Presentable a) => EdnsOption a where
    optNum     :: forall b -> b ~ a => OptNum
    optPres    :: forall b -> b ~ a => Builder -> Builder
    optEncode  :: OptEncode a
    optDecode  :: forall b -> b ~ a => OptDecode a

    optPres t = present $ optNum t
    {-# INLINE optPres #-}

-- | Existentially quantified type-opaque 'EdnsOption', with heterogeneous
-- equality.
data SomeOption = forall a. EdnsOption a => SomeOption a

-- | Extract specific known 'EdnsOption' from existential wrapping
fromOption :: forall a. EdnsOption a => SomeOption -> Maybe a
fromOption (SomeOption a) = cast a
{-# INLINE fromOption #-}

instance Show SomeOption where
    showsPrec p (SomeOption a)  = showsP p $
        showString "SomeOption " . shows' a

instance Presentable SomeOption where
    present (SomeOption a)  = present a
    {-# INLINE present #-}

instance Eq SomeOption where
    (SomeOption (_a :: a)) == (SomeOption (_b :: b)) =
        case teq a b of
            Just Refl -> _a == _b
            _         -> False

optionCode :: SomeOption -> OptNum
optionCode (SomeOption (_ :: a)) = optNum a
{-# INLINE optionCode #-}

monoOption :: forall a t. (EdnsOption a, Foldable t) => t SomeOption -> [a]
monoOption = foldr (maybe id (:) . fromOption) []
{-# INLINE monoOption #-}

{-# INLINE putOption #-}
putOption :: OptEncode SomeOption
putOption (SomeOption (o :: a)) = do
    put16 $ coerce (optNum a)
    passLen (optEncode o)

--------

-- | Option Control structure for configuring EDNS options for queries
newtype OptionCtl = OptionCtl { fromOptionCtl :: [SomeOption] }
    deriving (Eq, Show)

-- | Clear all previously included EDNS options and replace with the provided
-- list of options
optCtlSet :: [SomeOption] -> OptionCtl -> OptionCtl
optCtlSet opts _ = OptionCtl (sortOn optionCode opts)

-- | Add the provided list of options to the old set of options, omitting
-- those from the old set whose OPTCODE coincides with at least one element in
-- the new set. Otherwise, options with the same @OPTCODE@ value are preserved
-- if they appear in the same set (old or new).
optCtlAdd :: [SomeOption] -> OptionCtl -> OptionCtl
optCtlAdd opts (OptionCtl opts') = OptionCtl $ lbMerge (sortOn optionCode opts) opts'
  where
    -- left-biased merge that omits duplicate opcodes in the second argument only
    lbMerge [] ys = ys
    lbMerge xs [] = xs
    lbMerge xs@(x:xt) ys@(y:yt) =
        case compare (optionCode x) (optionCode y) of
            LT -> x : lbMerge xt ys
            GT -> y : lbMerge xs yt
            EQ -> lbMerge xs yt

-- | Empty set of EDNS options
emptyOptionCtl :: OptionCtl
emptyOptionCtl = OptionCtl []

-- | Unlift an endomorphism over 'OptionCtl' to an endomorphism over @['SomeOption']@
applyOptionCtl :: (OptionCtl -> OptionCtl) -> [SomeOption] -> [SomeOption]
applyOptionCtl f opts = fromOptionCtl $ f (OptionCtl opts)
