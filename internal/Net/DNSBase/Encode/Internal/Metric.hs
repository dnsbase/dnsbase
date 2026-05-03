-- |
-- Module      : Net.DNSBase.Encode.Internal.Metric
-- Description : TBD
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
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
    , mbIPv4
    , mbIPv6
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Short as SB

import Net.DNSBase.Internal.Util

-- Auto-instantiated monoid that is coercible to and from SizedBuilder
-- and naturally specifies the proper semantics of each tuple element
type MonoMetricBuilder = (Sum Int, All, Builder)

-- | Monoidal wrapper over Builder monoid that internally records
-- the total length of the Builder output and maintains a flag
-- for post-hoc error checking
newtype SizedBuilder = SizedBuilder_ (Int, Bool, Builder)

instance Monoid SizedBuilder where
    mempty = coerce (mempty :: MonoMetricBuilder)

-- | The semigroup operation is strict in all the elements of the tuple.
instance Semigroup SizedBuilder where
    {-# INLINE (<>) #-}
    x<>y = _force $ _mono x <> _mono y

{-# INLINE _mono #-}
_mono :: SizedBuilder -> MonoMetricBuilder
_mono = coerce

{-# INLINE _force #-}
_force :: MonoMetricBuilder -> SizedBuilder
_force m = case coerce m of
    a@(StrictMB _ _ _) -> a

------------------ Pattern synonyms

pattern StrictMB :: Int -> Bool -> Builder -> SizedBuilder
pattern StrictMB n t b <- SizedBuilder_ (!n, !t, !b) where
  StrictMB !n !t !b = SizedBuilder_ (n, t, b)
{-# COMPLETE StrictMB #-}

-- Set sticky tag that the builder state is broken
pattern Invalid :: SizedBuilder
pattern Invalid <- SizedBuilder_ ( _, False, _) where
  Invalid = SizedBuilder_ (0, False, mempty)

pattern Valid :: Int -> Builder -> SizedBuilder
pattern Valid n b <- SizedBuilder_ (!n, True, b) where
  Valid !n b = SizedBuilder_ (n, True, b)
{-# COMPLETE Valid, Invalid #-}

-- | Extract length and builder when valid.
pattern SizedBuilder :: Int -> Builder -> SizedBuilder
pattern SizedBuilder n b <- SizedBuilder_ (!n, True, b)
{-# COMPLETE SizedBuilder, Invalid #-}

-- | SizedBuilder representing an unspecified error, probably
-- one of the inputs was too long.
mbErr :: SizedBuilder
mbErr = Invalid

-- internal constructors for fixed and variable -length values
_constlen ::       Int  -> (a -> Builder) -> a -> SizedBuilder
_varlen   :: (a -> Int) -> (a -> Builder) -> a -> SizedBuilder
_constlen !i !f = \x -> Valid i (f x)
_varlen   !l !f = \x -> Valid (l x) (f x)
{-# INLINE _constlen #-}
{-# INLINE _varlen #-}

-- | Encode an unsigned 8-bit number.
mbWord8 :: Word8 -> SizedBuilder
mbWord8 = _constlen 1 B.word8
{-# INLINE mbWord8 #-}

-- | Encode an unsigned 16-bit number in network byte order.
mbWord16 :: Word16 -> SizedBuilder
mbWord16 = _constlen 2 B.word16BE
{-# INLINE mbWord16 #-}

-- | Encode an unsigned 32-bit number in network byte order.
mbWord32 :: Word32 -> SizedBuilder
mbWord32 = _constlen 4 B.word32BE
{-# INLINE mbWord32 #-}

-- | Encode an unsigned 64-bit number in network byte order.
mbWord64 :: Word64 -> SizedBuilder
mbWord64 = _constlen 8 B.word64BE
{-# INLINE mbWord64 #-}

{-# INLINE mbInt8 #-}
{-# INLINE mbInt16 #-}
mbInt8, mbInt16 :: Int -> SizedBuilder
mbInt8  = _constlen 1 (B.int8    . fromIntegral)
mbInt16 = _constlen 2 (B.int16BE . fromIntegral)

-- | Encode a "ByteString" of up to approximately 65535 bytes.  In practice the
-- limit is smaller since the entire DNS packet has a 16-bit length limit.
mbByteString :: ByteString -> SizedBuilder
mbByteString b
    | !len <- B.length b
    , len <= 0xffff = Valid len (B.byteString b)
    | otherwise     = mbErr

-- | Encode a length-tagged "ByteString" of up to 255 bytes.
mbByteStringLen8 :: ByteString -> SizedBuilder
mbByteStringLen8 b
    | !len <- B.length b
    , len <= 0xff = mbInt8 len <> Valid len (B.byteString b)
    | otherwise   = mbErr

-- | Encode a length-tagged ByteString of up to approximately 65535 bytes.  In
-- practice the limit is smaller since the entire DNS packet has a 16-bit
-- length limit.
mbByteStringLen16 :: ByteString -> SizedBuilder
mbByteStringLen16 b
    | !len <- B.length b
    , len <= 0xffff = mbInt16 len <> Valid len (B.byteString b)
    | otherwise     = mbErr

-- | Encode a "ShortByteString" of up to approximately 65535 bytes.  In
-- practice the limit is smaller since the entire DNS packet has a 16-bit
-- length limit.
mbShortByteString :: ShortByteString -> SizedBuilder
mbShortByteString b
    | !len <- SB.length b
    , len <= 0xffff = Valid len (B.shortByteString b)
    | otherwise     = mbErr

-- | Encode a "ShortByteString" of up to 255 bytes, preceded by its length.
mbShortByteStringLen8 :: ShortByteString -> SizedBuilder
mbShortByteStringLen8 b
    | len <- SB.length b
    , l8 <- fromIntegral len
    , len <= 0xff = Valid (len + 1) (B.word8 l8 <> B.shortByteString b)
    | otherwise   = mbErr

-- | Encode a length-tagged ByteString of up to approximately 65535 bytes.  In
-- practice the limit is smaller since the entire DNS packet has a 16-bit
-- length limit.
mbShortByteStringLen16 :: ShortByteString -> SizedBuilder
mbShortByteStringLen16 b
    | len <- SB.length b
    , len <= 0xffff = mbInt16 len <> Valid len (B.shortByteString b)
    | otherwise     = mbErr

-- | Encode an IPv4 address
mbIPv4 :: IPv4 -> SizedBuilder
mbIPv4 = _constlen 4 (B.word32BE . fromIPv4w)

-- | Encode an IPv4 address
mbIPv6 :: IPv6 -> SizedBuilder
mbIPv6 = _constlen 16 \ (fromIPv6w -> (w1, w2, w3, w4)) ->
    B.word32BE w1 <> B.word32BE w2 <> B.word32BE w3 <> B.word32BE w4
