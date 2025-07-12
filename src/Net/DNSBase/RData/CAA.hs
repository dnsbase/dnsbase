{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.RData.CAA
    ( -- * Certification Authority Authorisation
      T_caa(..)
    , validCaaTag
    ) where

import qualified Data.ByteString.Short as SB

import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE
import Net.DNSBase.Text

-- | [CAA RDATA](https://www.rfc-editor.org/rfc/rfc8659.html#section-4.1)
--
-- Note that tags are treated case-sensitively when comparing @CAA@ 'RData'
-- objects.  Case-insensitive treatment of the tags is an application-layer
-- concern.
--
data T_caa = T_CAA
    { caaFlags :: Word8
    , caaTag   :: ShortByteString
    , caaValue :: ShortByteString }
    deriving (Typeable, Eq, Show)

instance Ord T_caa where
    a `compare` b = caaFlags  a `compare` caaFlags  b
                 <> tagLength a `compare` tagLength b
                 <> caaTag    a `compare` caaTag    b
                 <> caaValue  a `compare` caaValue  b
      where
        tagLength = SB.length . caaTag

instance Presentable T_caa where
    present T_CAA{..}
        = present caaFlags
          . presentSp caaTag
          . presentSp @DnsText (coerce caaValue)

instance KnownRData T_caa where
    rdType     = CAA
    rdEncode T_CAA{..}
        | validCaaTag caaTag = putSizedBuilder $
                                   mbWord8 caaFlags
                                <> mbShortByteStringLen8 caaTag
                                <> mbShortByteString caaValue
        | otherwise         = failWith CantEncode
    rdDecode _ len = do
        caaFlags <- get8
        tlen     <- getInt8
        caaTag   <- getShortNByteString tlen
        when (not $ validCaaTag caaTag) $ failSGet "CAA tag not alphanumeric"
        caaValue <- getShortNByteString (len - tlen - 2)
        pure $ RData T_CAA{..}

-- | Validate CAA tag length and content
validCaaTag :: ShortByteString -> Bool
validCaaTag = (&&) <$> not . SB.null <*> SB.all isalnum
  where
    isalnum w = w - 0x30 < 10 || (w .&. 0xdf) - 0x41 < 26
