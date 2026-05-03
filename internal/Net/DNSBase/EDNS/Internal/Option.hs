-- |
-- Module      : Net.DNSBase.EDNS.Internal.Option
-- Description : TBD
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
{-# LANGUAGE ConstraintKinds #-}
{-# LANGUAGE DefaultSignatures #-}
module Net.DNSBase.EDNS.Internal.Option
    ( -- * EDNS option class
      KnownEdnsOption(..)
    , EdnsOption(..)
    , fromOption
    , monoOption
    , optionCode
    , putOption
    -- * EDNS option Controls
    , OptionCtl
    , optCtlSet
    , optCtlAdd
    , emptyOptionCtl
    , applyOptionCtl
    -- * Extensibility
    , OptionCodec(..)
    ) where

import Data.List (sortOn)

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.EDNS.Internal.OptNum
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

-- | EDNS option class with conversion to/from opaque 'EdnsOption' form.
class (Typeable a, Eq a, Show a, Presentable a) => KnownEdnsOption a where
    -- | The codec-consumed extension value for option type @a@.
    -- Defaults to @()@.  Options with a non-trivial extension
    -- (currently only 'Net.DNSBase.EDNS.Option.EDE.O_ede', whose extension carries the
    -- info-code name registry) supply their own associated-type
    -- definition.
    type OptionExtensionVal a :: Type
    type OptionExtensionVal a = ()

    -- | The library's built-in starting 'OptionExtensionVal' for option
    -- type @a@.  Used as the baseline when the library installs
    -- its built-in registration for @a@, and as the starting
    -- point when the user extends the codec for @a@.  For
    -- @'OptionExtensionVal' a ~ ()@ options the class default applies.
    optionExtensionVal :: forall b -> b ~ a => OptionExtensionVal a
    default optionExtensionVal :: (OptionExtensionVal a ~ ())
                               => forall b -> b ~ a
                               => OptionExtensionVal a
    optionExtensionVal _ = ()

    -- | The EDNS option number
    optNum     :: forall b -> b ~ a => OptNum

    -- | CPS option number presentation form builder.
    -- Most useful for new option values not yet known to the library.
    optPres    :: forall b -> b ~ a => Builder -> Builder

    -- | Encoder of option data to wire form
    optEncode  :: forall s r. (Typeable r, Eq r, Show r)
               => a -- ^ The value to encode
               -> SPut s r

    -- | Decoder from wire form
    optDecode  :: forall b
               -> b ~ a
               -- ^ The type to decode
               => OptionExtensionVal b
               -- ^ Its extension value
               -> Int
               -- ^ The encoded data length
               -> SGet EdnsOption

    optPres t = present $ optNum t
    {-# INLINE optPres #-}


-- | Known EDNS option Proxy + 'OptionExtensionVal' pair, paralleling
-- 'Net.DNSBase.Internal.RData.RDataCodec' on the RR-type side.
data OptionCodec where
    OptionCodec :: KnownEdnsOption a
                => Proxy a
                -> OptionExtensionVal a
                -> OptionCodec

-- | Existentially quantified type-opaque 'KnownEdnsOption', with heterogeneous
-- equality.
data EdnsOption = forall a. KnownEdnsOption a => EdnsOption a

-- | Extract specific 'KnownEdnsOption' from existential wrapping
fromOption :: forall a. KnownEdnsOption a => EdnsOption -> Maybe a
fromOption (EdnsOption a) = cast a
{-# INLINE fromOption #-}

instance Show EdnsOption where
    showsPrec p (EdnsOption a)  = showsP p $
        showString "EdnsOption " . shows' a

instance Presentable EdnsOption where
    present (EdnsOption a)  = present a
    {-# INLINE present #-}

instance Eq EdnsOption where
    (EdnsOption (_a :: a)) == (EdnsOption (_b :: b)) =
        case teq a b of
            Just Refl -> _a == _b
            _         -> False

-- | The 16-bit 'Net.DNSBase.EDNS.OptNum.OptNum' codepoint of the option wrapped inside a
-- 'EdnsOption'.  Useful for filtering or grouping a heterogeneous
-- option list without unpacking each value.
optionCode :: EdnsOption -> OptNum
optionCode (EdnsOption (_ :: a)) = optNum a
{-# INLINE optionCode #-}

-- | Filter a 'Foldable' of 'EdnsOption' down to the values of a
-- single type @a@, dropping any entries whose option-code does
-- not match (or whose value is held under an 'Net.DNSBase.EDNS.Option.Opaque.OpaqueOption' even
-- though @a@ is registered for that code).  Use a type
-- application to select the target type, e.g. @'monoOption' \@'Net.DNSBase.EDNS.Option.EDE.O_ede'
-- ednsOptions@.
monoOption :: forall a t. (KnownEdnsOption a, Foldable t) => t EdnsOption -> [a]
monoOption = foldr (maybe id (:) . fromOption) []
{-# INLINE monoOption #-}

-- | Wire-form encoder for a 'EdnsOption': writes the 16-bit
-- option code followed by the length-prefixed value bytes
-- produced by the underlying 'optEncode' method.  Used by the
-- OPT pseudo-RR encoder to serialise each option in turn.
putOption :: forall s r. (Typeable r, Eq r, Show r)
          => EdnsOption -> SPut s r
putOption (EdnsOption (o :: a)) = do
    put16 $ coerce (optNum a)
    passLen (optEncode o)
{-# INLINE putOption #-}

--------

-- | The list of EDNS options carried in the OPT pseudo-RR of an
-- outgoing query.  Callers do not build an 'OptionCtl' directly;
-- they build an endomorphism @'OptionCtl' -> 'OptionCtl'@ out of
-- 'optCtlAdd' and 'optCtlSet' and pass it to the 'Net.DNSBase.Resolver.EdnsOptionCtl'
-- pattern of 'Net.DNSBase.Resolver.QueryControls'.  The endomorphism is applied to the
-- resolver's ambient option list at send time, so callers see the
-- final list as a delta on top of whatever the resolver already
-- had configured.
newtype OptionCtl = OptionCtl { fromOptionCtl :: [EdnsOption] }
    deriving (Eq, Show)

-- | Replace the option list outright with the supplied options.
-- Use this when the per-call configuration should override
-- anything the resolver had set; combine with 'optCtlAdd' for
-- partial overrides.
optCtlSet :: [EdnsOption] -> OptionCtl -> OptionCtl
optCtlSet opts _ = OptionCtl (sortOn optionCode opts)

-- | Add the supplied options to the existing list.  When the new
-- and old options share an @OPTCODE@, the new entries replace the
-- old ones with that code.
optCtlAdd :: [EdnsOption] -> OptionCtl -> OptionCtl
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

-- | The empty option list.  Useful as the seed when running an
-- 'OptionCtl' endomorphism to inspect what it would produce.
emptyOptionCtl :: OptionCtl
emptyOptionCtl = OptionCtl []

-- | Apply an 'OptionCtl' endomorphism to a plain list of options.
-- Used by the resolver to fold per-call EDNS-option tweaks into
-- the option list it is about to put on the wire.
applyOptionCtl :: (OptionCtl -> OptionCtl) -> [EdnsOption] -> [EdnsOption]
applyOptionCtl f opts = fromOptionCtl $ f (OptionCtl opts)
