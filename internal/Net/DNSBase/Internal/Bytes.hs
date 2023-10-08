module Net.DNSBase.Internal.Bytes
    ( Bytes16(..)
    , Bytes32(..)
    , Bytes64(..)
    ) where

import qualified Data.Base16.Types as B16
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base32.Hex as B32
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Short as SB
import qualified Data.Text as T
import Data.String (IsString(..))

import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

-- | ByteStrings with a hexadecimal presentation form
newtype Bytes16 = Bytes16 { getShort16 :: ShortByteString }
    deriving (Eq, Ord, Semigroup, Monoid) via ShortByteString
instance Presentable Bytes16 where
    present = (<>) . B.byteStringHex . fromShort16
instance Show Bytes16 where
    showsPrec _ = shows . B16.extractBase16 . B16.encodeBase16' . fromShort16
instance IsString Bytes16 where
    fromString s = case B16.decodeBase16Untyped $ BS.pack s of
        Right bs -> toShort16 bs
        Left err -> error $ T.unpack err


-- | ByteStrings with a base32 presentation form
newtype Bytes32 = Bytes32 { getShort32 :: ShortByteString }
    deriving (Eq, Ord, Semigroup, Monoid) via ShortByteString
instance Presentable Bytes32 where
    present = present . B32.encodeBase32Unpadded' . fromShort32
instance Show Bytes32 where
    showsPrec _ = shows . B32.encodeBase32Unpadded' . fromShort32
instance IsString Bytes32 where
    fromString s = case B32.decodeBase32Unpadded $ BS.pack s of
        Right bs -> toShort32 bs
        Left err -> error $ T.unpack err


-- | ByteStrings with a base64 presentation form
newtype Bytes64 = Bytes64 { getShort64 :: ShortByteString }
    deriving (Eq, Ord, Semigroup, Monoid) via ShortByteString
instance Presentable Bytes64 where
    present = present . B64.encodeBase64' . fromShort64
instance Show Bytes64 where
    showsPrec _ = shows . B64.encodeBase64' . fromShort64
instance IsString Bytes64 where
    fromString s = case B64.decodeBase64 $ BS.pack s of
        Right bs -> toShort64 bs
        Left err -> error $ T.unpack err

fromShort16 :: Bytes16 -> ByteString
fromShort16 = SB.fromShort . coerce

fromShort32 :: Bytes32 -> ByteString
fromShort32 = SB.fromShort . coerce

fromShort64 :: Bytes64 -> ByteString
fromShort64 = SB.fromShort . coerce

toShort16 :: ByteString -> Bytes16
toShort16 = coerce . SB.toShort

toShort32 :: ByteString -> Bytes32
toShort32 = coerce . SB.toShort

toShort64 :: ByteString -> Bytes64
toShort64 = coerce . SB.toShort
