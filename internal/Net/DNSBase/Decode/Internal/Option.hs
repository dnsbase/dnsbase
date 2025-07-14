module Net.DNSBase.Decode.Internal.Option
    ( OptionMap
    , T_opt(..)
    , emptyOptionMap
    , getOPTWith
    ) where

import qualified Data.IntMap.Strict as IM

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.EDNS.Internal.Option.Opaque
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.Util

-- | [OPT RDATA](https://tools.ietf.org/html/rfc6891#section-6.1.2).
-- More precisely, just the EDNS option list of @OPT@ pseudo-RR.
-- The fixed fields are part of the 'DNSMessage' metadata.
--
-- Used only internally while decoding messages, not user-visible.
--
-- The variable part of an OPT RR may contain zero or more options in
-- the RDATA.  Each option MUST be treated as a bit field.  Each option
-- is encoded as:
--
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- > |                          OPTION-CODE                          |
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- > |                         OPTION-LENGTH                         |
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- > |                                                               |
-- > /                          OPTION-DATA                          /
-- > /                                                               /
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
--
-- Neither name compression nor canonical ordering are applicable here.
-- This datatype has no 'Ord' instance.
--
newtype T_opt = T_OPT [SomeOption]
instance Eq  T_opt         where (==) = unreachable
instance Ord T_opt         where compare = unreachable
instance Presentable T_opt where present = unreachable
instance Show T_opt        where showsPrec = unreachable
instance KnownRData T_opt  where
    rdType _ = OPT
    rdEncode = unreachable
    rdDecode _ = unreachable

unreachable :: a
unreachable = errorWithoutStackTrace "Unreachable method of internal data type"

-- | Table of known EDNS option type decoders
type OptionMap = IM.IntMap (Int -> SGet SomeOption)

-- | Empty EDNS option decoder map
emptyOptionMap :: OptionMap
emptyOptionMap = IM.empty

-- | Decoder for the @OPT@ pseudo-RR using a custom set of EDNS option
-- decoders.
--
getOPTWith :: OptionMap -- ^ OPTCODE->decoder map
           -> Int       -- ^ OPT RData length
           -> SGet RData
getOPTWith optmap = RData . T_OPT <.> getOptions
  where
    getOptions :: Int -> SGet [SomeOption]
    getOptions 0 = pure []
    getOptions rdlen = do
        code <- get16
        len  <- getInt16
        opt  <- case IM.lookup (fromIntegral code) optmap of
            Nothing -> opaqueOption code . coerce <$> getShortNByteString len
            Just dc -> fitSGet len $ dc len
        (opt :) <$> getOptions (rdlen - (len + 4))
