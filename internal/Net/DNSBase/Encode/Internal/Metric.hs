module Net.DNSBase.Encode.Internal.Metric
    ( SizedBuilder
    -- exported pattern
    , pattern SizedBuilder
    -- exported converters
    , mbErr
    , mbWord8
    , mbWord16
    , mbWord32
    , mbWord64
    , mbByteString
    , mbByteStringLen8
    , mbByteStringLen16
    , mbShortByteString
    , mbShortByteStringLen8
    , mbShortByteStringLen16
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Short as SB

import Net.DNSBase.Internal.Util

-- Auto-instantiated monoid that is coercible to and from MetricBuilder
-- and naturally specifies the proper semantics of each tuple element
type MonoMetricBuilder = (Sum Int, All, Builder)

-- | Monoidal wrapper over Builder monoid that internally records
-- the total length of the Builder output and maintains a flag
-- for post-hoc error checking
newtype MetricBuilder = MetricBuilder (Int, Bool, Builder)
type SizedBuilder = MetricBuilder

instance Monoid MetricBuilder where
    mempty = coerce (mempty :: MonoMetricBuilder)

-- | The semigroup operation is strict in all the elements of the tuple.
instance Semigroup MetricBuilder where
    {-# INLINE (<>) #-}
    x<>y = _force $ _mono x <> _mono y

{-# INLINE _mono #-}
_mono :: MetricBuilder -> MonoMetricBuilder
_mono = coerce

{-# INLINE _force #-}
_force :: MonoMetricBuilder -> MetricBuilder
_force m = case coerce m of
    a@(StrictMB _ _ _) -> a

------------------ Pattern synonyms

{-# COMPLETE StrictMB #-}
pattern StrictMB :: Int -> Bool -> Builder -> MetricBuilder
pattern StrictMB n t b <- MetricBuilder (!n, !t, !b) where
  StrictMB !n !t !b = MetricBuilder (n, t, b)

{-# COMPLETE Valid, Invalid #-}
-- Set sticky tag that the builder state is broken
pattern Invalid :: MetricBuilder
pattern Invalid <- MetricBuilder ( _, False, _) where
  Invalid = MetricBuilder (0, False, mempty)

pattern Valid :: Int -> Builder -> MetricBuilder
pattern Valid n b <- MetricBuilder (!n, True, b) where
  Valid !n b = MetricBuilder (n, True, b)

-- | Extract length and builder when valid.
{-# COMPLETE SizedBuilder, Invalid #-}
pattern SizedBuilder :: Int -> Builder -> MetricBuilder
pattern SizedBuilder n b <- MetricBuilder (!n, True, b)

-- | MetricBuilder representing an unspecified error, probably
-- one of the inputs was too long.
mbErr :: MetricBuilder
mbErr = Invalid

-- internal constructors for fixed and variable -length values
_constlen ::       Int  -> (a -> Builder) -> a -> MetricBuilder
_varlen   :: (a -> Int) -> (a -> Builder) -> a -> MetricBuilder
_constlen !i !f = \x -> Valid i (f x)
_varlen   !l !f = \x -> Valid (l x) (f x)
{-# INLINE _constlen #-}
{-# INLINE _varlen #-}

-- | Encode an unsigned 8-bit number.
mbWord8 :: Word8 -> MetricBuilder
mbWord8 = _constlen 1 B.word8
{-# INLINE mbWord8 #-}

-- | Encode an unsigned 16-bit number in network byte order.
mbWord16 :: Word16 -> MetricBuilder
mbWord16 = _constlen 2 B.word16BE
{-# INLINE mbWord16 #-}

-- | Encode an unsigned 32-bit number in network byte order.
mbWord32 :: Word32 -> MetricBuilder
mbWord32 = _constlen 4 B.word32BE
{-# INLINE mbWord32 #-}

-- | Encode an unsigned 64-bit number in network byte order.
mbWord64 :: Word64 -> MetricBuilder
mbWord64 = _constlen 8 B.word64BE
{-# INLINE mbWord64 #-}

{-# INLINE mbInt8 #-}
{-# INLINE mbInt16 #-}
mbInt8, mbInt16 :: Int -> MetricBuilder
mbInt8  = _constlen 1 (B.int8    . fromIntegral)
mbInt16 = _constlen 2 (B.int16BE . fromIntegral)

-- | Encode a "ByteString" of up to approximately 65535 bytes.  In practice the
-- limit is smaller since the entire DNS packet has a 16-bit length limit.
mbByteString :: ByteString -> MetricBuilder
mbByteString b
    | !len <- B.length b
    , len <= 0xffff = Valid len (B.byteString b)
    | otherwise     = mbErr

-- | Encode a length-tagged "ByteString" of up to 255 bytes.
mbByteStringLen8 :: ByteString -> MetricBuilder
mbByteStringLen8 b
    | !len <- B.length b
    , len <= 0xff = mbInt8 len <> Valid len (B.byteString b)
    | otherwise   = mbErr

-- | Encode a length-tagged ByteString of up to approximately 65535 bytes.  In
-- practice the limit is smaller since the entire DNS packet has a 16-bit
-- length limit.
mbByteStringLen16 :: ByteString -> MetricBuilder
mbByteStringLen16 b
    | !len <- B.length b
    , len <= 0xffff = mbInt16 len <> Valid len (B.byteString b)
    | otherwise     = mbErr

-- | Encode a "ShortByteString" of up to approximately 65535 bytes.  In
-- practice the limit is smaller since the entire DNS packet has a 16-bit
-- length limit.
mbShortByteString :: ShortByteString -> MetricBuilder
mbShortByteString b
    | !len <- SB.length b
    , len <= 0xffff = Valid len (B.shortByteString b)
    | otherwise     = mbErr

-- | Encode a "ShortByteString" of up to 255 bytes, preceded by its length.
mbShortByteStringLen8 :: ShortByteString -> MetricBuilder
mbShortByteStringLen8 b
    | len <- SB.length b
    , l8 <- fromIntegral len
    , len <= 0xff = Valid (len + 1) (B.word8 l8 <> B.shortByteString b)
    | otherwise   = mbErr

-- | Encode a length-tagged ByteString of up to approximately 65535 bytes.  In
-- practice the limit is smaller since the entire DNS packet has a 16-bit
-- length limit.
mbShortByteStringLen16 :: ShortByteString -> MetricBuilder
mbShortByteStringLen16 b
    | len <- SB.length b
    , len <= 0xffff = mbInt16 len <> Valid len (B.shortByteString b)
    | otherwise     = mbErr
