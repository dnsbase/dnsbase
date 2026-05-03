-- |
-- Module      : Net.DNSBase.Decode.Internal.Option
-- Description : TBD
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
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
-- The fixed fields are part of the 'Net.DNSBase.Message.DNSMessage' metadata.
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
newtype T_opt = T_OPT [EdnsOption]
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

-- | Table of known EDNS option type codecs, paralleling
-- 'RDataMap' on the RR-type side.
type OptionMap = IM.IntMap OptionCodec

-- | Empty EDNS option codec map
emptyOptionMap :: OptionMap
emptyOptionMap = IM.empty

-- | Decoder for the @OPT@ pseudo-RR using a custom set of EDNS option
-- codecs.
--
getOPTWith :: OptionMap -- ^ OPTCODE->codec map
           -> Int       -- ^ OPT RData length
           -> SGet RData
getOPTWith optmap = RData . T_OPT <.> getOptions
  where
    getOptions :: Int -> SGet [EdnsOption]
    getOptions 0 = pure []
    getOptions rdlen = do
        code <- get16
        len  <- getInt16
        opt  <- case IM.lookup (fromIntegral code) optmap of
            Nothing -> opaqueEdnsOption code . coerce <$> getShortNByteString len
            Just (OptionCodec (_ :: Proxy a) opts) ->
                fitSGet len $ optDecode a opts len
        (opt :) <$> getOptions (rdlen - (len + 4))
