{-# LANGUAGE RecordWildCards #-}
module Net.DNSBase.Decode.Internal.RData
    ( emptyRDataMap
    , getRData
    , getRR
    , fromOpaque
    ) where

import qualified Data.IntMap as IM
import qualified Data.ByteString as B
import qualified Data.ByteString.Short as SB

import Net.DNSBase.Decode.Internal.Domain
import Net.DNSBase.Decode.Internal.Option
import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Nat16
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.RR
import Net.DNSBase.Internal.RRCLASS
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.Util
import Net.DNSBase.RData.Internal.XNAME

-- | 'RDataMap' without any registered mappings
emptyRDataMap :: RDataMap
emptyRDataMap = IM.empty

-- | Performs a lookup operation for the decoder associated with a given RRTYPE
-- (as 'Word16') against the provided 'RDataMap', and runs the appropriate
-- RData decoder (defaulting to 'OpaqueRData' on lookup miss) using the
-- provided length argument.
getRData :: RDataMap        -- ^ Known decoders
         -> Maybe OptionMap -- ^ Known EDNS option decoders
         -> Word16          -- ^ 'RRTYPE' to decode, as 'Word16'
         -> Int             -- ^ Length of RData in bytes (RDLENGTH)
         -> SGet RData
getRData _ (Just om) (RRTYPE -> OPT)   = getOPTWith om
getRData _ Nothing   t@(RRTYPE -> OPT) = opaqueDecoder t
getRData dm _ (dmLookup dm -> Just dc) = decodeWith dc
getRData _  _ t                        = opaqueDecoder t

decodeWith :: SomeCodec -> Int -> SGet RData
decodeWith (SomeCodec (_ :: proxy a) (opts :: CodecOpts a)) =
    rdDecode @a opts

-- | Decode unknown RRs as opaque data.  This includes unexpected OPT records
-- in the answer or authority sections.
opaqueDecoder :: Word16 -> Int -> SGet RData
opaqueDecoder rrtype len = do
    dat <- coerce <$> getShortNByteString len
    return $ opaqueRData rrtype dat

-- | Convert 'RData' to its Known equivalent of the same RRtype.
-- If the input value is already non-opaque, or if there's no entry for the
-- 'RRTYPE' in the provided 'RDataMap', the input will be returned as-is.
--
-- Otherwise, this will attempt to decode the opaque record without name
-- compression, the decode may fail, and an error reason returned instead.
--
fromOpaque :: RDataMap -> RData -> Either DNSError RData
fromOpaque dm rd@(rdataType -> t) = case wordToNat16 $ coerce t of
    SomeNat16 (_ :: proxy n)
        | Just dc <- dmLookup dm $ fromIntegral t
        , Just (OpaqueRData d :: OpaqueRData n) <- fromRData rd
        , bs <- SB.fromShort (coerce d)
        , len <- B.length bs
          -> decodeAtWith 0 False (decodeWith dc len) bs
        | otherwise -> Right rd

-- | Look up type-specific decoder.
dmLookup :: RDataMap -> Word16 -> Maybe SomeCodec
dmLookup dm typ = IM.lookup (fromIntegral typ) dm

-- | Decoder for a resource record, shares owner names of consecutive
-- RRs or names of CNAME targets with adjacent RRs for the target
-- (intervening RRSIGs for the CNAME don't reset the target).
getRR :: RDataMap -> Maybe OptionMap -> SGet RR
getRR dm om = do
    owner   <- getLastOwner
    cname   <- getLastCname
    rrOwner <- setLastOwner =<< dedup owner cname <$> getDomain
    typ     <- get16
    rrClass <- getRRCLASS
    local (setDecodeTriple (DnsTriple rrOwner (coerce typ) rrClass)) do
        rrTTL   <- get32
        len     <- getInt16
        rrData  <- fitSGet len $
                       if | typ == coerce CNAME ->
                            RData . T_CNAME <$> (setLastCname =<< getDomain)
                          | otherwise -> getRData dm om typ len
        return RR{..}
  where
    getRRCLASS = RRCLASS <$> get16
    dedup n1 n2 name | name == n1 = n1
                     | name == n2 = n2
                     | otherwise = name
