{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.RData.WKS
    ( T_wks(..)
    , WksProto(.., UDP, TCP)
    ) where

import qualified Data.Set as Set
import qualified Data.Primitive.ByteArray as A
import Data.Set (Set, fromAscList)
import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE

newtype WksProto = WksProto Word8
    deriving newtype (Eq, Ord, Bounded, Enum, Num, Real, Integral, Show, Read)

pattern TCP :: WksProto; pattern TCP = WksProto 6
pattern UDP :: WksProto; pattern UDP = WksProto 17

instance Presentable WksProto where
    present UDP = present @String "UDP"
    present TCP = present @String "TCP"
    present p   = present @Word8 $ fromIntegral p

-- | [WKS RDATA](https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.2).
-- Obsolete mapping of IP address to list of well-known services.
--
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  |                    ADDRESS                    |
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  |       PROTOCOL        |                       |
-- >  +--+--+--+--+--+--+--+--+                       |
-- >  |                                               |
-- >  /                   <BIT MAP>                   /
-- >  /                                               /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
data T_wks = T_WKS
    { wksAddr4 :: IPv4       -- ^ Host IPv4 address
    , wksProto :: WksProto   -- ^ IP protocol number
    , wksPorts :: Set Word16 -- ^ Set of port numbers
    } deriving (Typeable, Eq, Show)

instance Ord T_wks where
    a `compare` b = wksAddr4 a `compare` wksAddr4 b
                 <> wksProto a `compare` wksProto b
                 <> portlist a `compare` portlist b
      where
        portlist :: T_wks -> [Down Word16]
        portlist = coerce . Set.toList . wksPorts

instance Presentable T_wks where
    present T_WKS{..} =
        present          wksAddr4
        . presentSp      wksProto
        . presentSpPorts wksPorts
      where
        presentSpPorts (Set.toList -> ports) =
            present @String " ("
            . flip (foldr presentSp) ports
            . present @String " )"

instance KnownRData T_wks where
    rdType     = WKS
    {-# INLINE rdType #-}
    rdEncode T_WKS{..} = do
        putIPv4 wksAddr4
        put8 $ coerce wksProto
        putPortBitmap wksPorts
    rdDecode _ len = do
        wksAddr4 <- getIPv4
        wksProto <- WksProto <$> get8
        wksPorts <- getPortBitmap (len - 5)
        pure $ RData T_WKS{..}

getPortBitmap :: Int -> SGet (Set Word16)
getPortBitmap len
    | len > 0x2000 = failSGet "WKS bitmap too long"
    | otherwise    = fromAscList . go 0 <$> getNBytes len
  where
    go :: Word16 -> [Word8] -> [Word16]
    go !off (w : ws)
        | z <- countLeadingZeros w
        , z < 8
        , port <- off .|. fromIntegral z
          = port : go off (w `clearBit` (7-z) : ws)
        | otherwise = go (off + 8) ws
    go _ _ = []

putPortBitmap :: Set Word16 -> SPut s RData
putPortBitmap s
    | Set.null s = pure ()
    | otherwise  = putShortByteString sbs
  where
    top = fromIntegral $ Set.findMax s `shiftR` 3
    sbs = baToShortByteString bitmap
      where
        bitmap :: ByteArray
        bitmap = A.runByteArray do
            a <- A.newByteArray $ top + 1
            A.fillByteArray a 0 (top + 1) 0
            sequence_
                [ modifyArray a byte (`setBit` bitpos)
                | t <- Set.toList s
                , let it = fromIntegral t
                , let byte = (it `shiftR` 3)
                , let bitpos = 7 - (it .&. 0x7) ]
            pure a
