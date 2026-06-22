-- |
-- Module      : Net.DNSBase.Internal.Util
-- Description : TBD
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
module Net.DNSBase.Internal.Util
    ( (&), (.=), (<.>), (<$.>)
    , bool, cond
    , compose4
    , ByteArray(..), baToShortByteString, modifyArray
    , sbsToByteArray, sbsToMutableByteArray, copyFpToMBA, unsafeMBAToSBS
    , Down(..), comparing
    , (.|.), (.&.), clearBit, countLeadingZeros, complement, setBit
    , shiftL, shiftR, testBit, unsafeShiftL, unsafeShiftR
    , (<|>), (>=>), forM, forM_, guard, join, mzero, replicateM, unless, void, when
    , lift, ExceptT(ExceptT), throwE, catchE, runExceptT, withExceptT
    , ByteString, Builder, ShortByteString(..), Text
    , Coercible, coerce
    , Int8, Int16, Int32, Int64
    , Word8, Word16, Word32, Word64, word16be, word32be, word64be, toBE
    , IP(..), IPv4, IPv6, fromIPv4w, fromIPv6b, fromIPv6w, toIPv4w, toIPv6b, toIPv6w
    , All(..), Sum(..)
    , catMaybes, fromMaybe, isJust, isNothing, listToMaybe
    , NonEmpty(..)
    , shows', showsP
    , Type, Typeable, (:~:)(..), Proxy(..), cast, teq
    , allocaBytesAligned, castPtr, copyBytes, byteSwap32
    , fillBytes, minusPtr, peek, peekElemOff, plusForeignPtr
    , unsafePerformFPIO
    , shortByteStringSliceB
    , primMapShortByteStringSliceBounded
    ) where

import qualified Data.Primitive.ByteArray as A
import qualified Data.ByteString.Short as SB
import qualified Data.ByteString.Builder.Internal as BI
import qualified Data.ByteString.Builder.Prim as BP
import qualified Data.ByteString.Builder.Prim.Internal as BPI
import Control.Applicative ((<|>))
import Control.Monad ( (>=>), forM, forM_, guard, join, mzero, replicateM )
import Control.Monad ( unless, void, when )
import Control.Monad.Primitive (unsafeIOToPrim, unsafePrimToIO)
import Control.Monad.ST (ST)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT(ExceptT), throwE, catchE, runExceptT, withExceptT)
import Data.Array.Byte (ByteArray(..), MutableByteArray(..))
import Data.Bits ((.|.), (.&.), clearBit, countLeadingZeros, complement)
import Data.Bits (setBit, shiftL, shiftR, testBit, unsafeShiftL, unsafeShiftR)
import Data.Bool (bool)
import Data.ByteString (ByteString)
import Data.ByteString.Builder (Builder)
import Data.ByteString.Internal (ByteString(..), accursedUnutterablePerformIO)
import Data.ByteString.Short (ShortByteString(SBS))
import Data.Coerce (Coercible, coerce)
import Data.Function ((&))
import Data.IP (IP(..), IPv4, IPv6)
import Data.IP (fromIPv4w, fromIPv6b, fromIPv6w, toIPv4w, toIPv6b, toIPv6w)
import Data.Int (Int64, Int32, Int16, Int8)
import Data.Kind (Type)
import Data.List.NonEmpty (NonEmpty(..))
import Data.Maybe (catMaybes, fromMaybe, isJust, isNothing, listToMaybe)
import Data.Monoid (All(..), Sum(..))
import Data.Ord (Down(..), comparing)
import Data.Proxy (Proxy(..))
import Data.Text (Text)
import Data.Type.Equality ((:~:)(..), testEquality)
import Data.Typeable (Typeable, cast)
import Data.Word (Word8, Word16, Word32, Word64, byteSwap16, byteSwap32, byteSwap64)
import Foreign (ForeignPtr, Ptr, allocaBytesAligned, castPtr, copyBytes)
import Foreign (fillBytes, minusPtr, peek, peekElemOff, plusForeignPtr, plusPtr)
import GHC.ByteOrder (ByteOrder(..), targetByteOrder)
import GHC.ForeignPtr (unsafeWithForeignPtr)
import Type.Reflection (TypeRep, pattern TypeRep)

(.=) :: Eq b => (a -> b) -> b -> (a -> Bool)
f .= (!x) = (==x).f
{-# INLINE (.=) #-}
infix 9 .=

-- | Map over a functor after composition, priority just below that of @'(.)'@.
(<.>) :: Functor m => (b -> c) -> (a -> m b) -> a -> m c
f <.> g = fmap f . g
{-# INLINE (<.>) #-}
infixr 8 <.>

-- | Right associative <$> with reduced priority.
(<$.>) :: Functor m => (a -> b) -> m a -> m b
(<$.>) = fmap
{-# INLINE (<$.>) #-}
infixr 2 <$.>

compose4 :: (e -> f) -> (a -> b -> c -> d -> e) -> (a -> b -> c -> d -> f)
f `compose4` g = \a b c d -> f $ g a b c d
{-# INLINE compose4 #-}

cond :: (a -> Bool) -> (a -> b) -> (a -> b) -> (a -> b)
cond p f g = \x -> bool g f (p x) x
{-# INLINE cond #-}

app_prec :: Int
app_prec = 10

-- | Show a constructor or function argument.
shows' :: Show a => a -> ShowS
shows' = showsPrec (app_prec + 1)

-- | Show a constructor with arguments.
showsP :: Int -> ShowS -> ShowS
showsP = showParen . (> 10)

toBE :: (a -> a) -> a -> a
toBE swap !x =
  case targetByteOrder of
    LittleEndian -> swap x
    BigEndian -> x
{-# INLINE toBE #-}

-- | Extremely unsafe, uses 'accursedUnutterablePerformIO' from
-- "Data.ByteString.Internal" and comes with all the associated caveats.
unsafePerformFPIO :: ForeignPtr a -> (Ptr a -> IO b) -> b
unsafePerformFPIO fp = accursedUnutterablePerformIO . unsafeWithForeignPtr fp
{-# INLINE unsafePerformFPIO #-}

-- | Caller must ensure the input is exactly 2-bytes long.
word16be :: ByteString -> Word16
word16be (BS fp 2) = unsafePerformFPIO fp $ \ptr -> do
    allocaBytesAligned 2 2 $ \buf -> do
        copyBytes buf ptr 2
        w16 <- peek $ castPtr buf
        pure $ toBE byteSwap16 w16
word16be _ = error "word16be invalid input"
{-# INLINE word16be #-}

-- | Caller must ensure the input is exactly 4-bytes long.
word32be :: ByteString -> Word32
word32be (BS fp 4) = unsafePerformFPIO fp $ \ptr -> do
    allocaBytesAligned 4 4 $ \buf -> do
        copyBytes buf ptr 4
        w32 <- peek $ castPtr buf
        pure $ toBE byteSwap32 w32
word32be _ = error "word32be invalid input"
{-# INLINE word32be #-}

-- | Caller must ensure the input is exactly 8-bytes long.
word64be :: ByteString -> Word64
word64be (BS fp 8) = unsafePerformFPIO fp $ \ptr -> do
    allocaBytesAligned 8 8 $ \buf -> do
        copyBytes buf ptr 8
        w64 <- peek $ castPtr buf
        pure $ toBE byteSwap64 w64
word64be _ = error "word64be invalid input"
{-# INLINE word64be #-}

----- Type equality

teq :: forall a -> forall b -> (Typeable a, Typeable b) => Maybe (a :~: b)
teq a b = testEquality (rep a) (rep b)
  where
    rep :: forall c -> Typeable c => TypeRep c
    rep _ = TypeRep
{-# INLINE teq #-}

----- Wrappers around "primitive" API

baToShortByteString :: ByteArray -> ShortByteString
baToShortByteString (ByteArray ba) = SBS ba

modifyArray :: MutableByteArray s -> Int -> (Word8 -> Word8) -> ST s ()
modifyArray marr i f = A.readByteArray marr i >>= A.writeByteArray marr i . f

sbsToByteArray :: ShortByteString -> ByteArray
sbsToByteArray (SBS ba) = (ByteArray ba)

sbsToMutableByteArray :: ShortByteString -> ST s (MutableByteArray s)
sbsToMutableByteArray sb@(SBS ba) =
    A.thawByteArray (ByteArray ba) 0 (SB.length sb)

-- Copy @n@ bytes from the input pointer into the mutable output
-- buffer at offset @dstOff@.  Crosses the IO\/ST bridge via
-- 'unsafeIOToPrim' \/ 'unsafePrimToIO': the 'ForeignPtr' unwrap
-- requires IO, while the 'MutableByteArray' lives in 'ST s'.
copyFpToMBA :: forall s. ForeignPtr Word8
            -> MutableByteArray s
            -> Int
            -> Int
            -> ST s ()
copyFpToMBA fp !dst !dstOff !n =
    unsafeIOToPrim @(ST s) $ unsafeWithForeignPtr @Word8 fp
                           $ \ p -> unsafePrimToIO $ cp dst dstOff p n
  where
    cp :: MutableByteArray s -> Int -> Ptr Word8 -> Int -> ST s ()
    cp = A.copyPtrToMutableByteArray

-- Shrink a mutable byte array to the payload size and free in
-- place, invalidating the original, which must not be used again.
--
unsafeMBAToSBS :: MutableByteArray s -> Int -> ST s ShortByteString
unsafeMBAToSBS !m !n = do
    A.shrinkMutableByteArray m n
    baToShortByteString <$> A.unsafeFreezeByteArray m

----- 'ShortByteString' slice builders

-- | Emit @len@ bytes starting at @off@ within @sbs@ as a 'Builder',
-- copying directly from the underlying byte array into the builder's
-- output buffer.  The caller is responsible for ensuring
-- @0 <= off@ and @off + len <= SB.length sbs@.
shortByteStringSliceB :: Int -> Int -> ShortByteString -> Builder
shortByteStringSliceB !off !len sbs
    | len <= 0  = mempty
    | otherwise = BI.ensureFree len <> BI.builder step
  where
    step :: forall r. BI.BuildStep r -> BI.BuildStep r
    step k (BI.BufferRange op opEnd) = do
        A.copyByteArrayToPtr op (sbsToByteArray sbs) off len
        k (BI.BufferRange (op `plusPtr` len) opEnd)

-- | Walk @len@ bytes starting at @off@ within @sbs@, applying a
-- 'BP.BoundedPrim Word8' to each byte and emitting the result into a
-- 'Builder'.  Equivalent to bytestring's 'BP.primMapByteStringBounded'
-- but sourced from an unpinned 'ShortByteString' slice rather than a
-- pinned 'ByteString'.  Handles output-buffer-full mid-slice by
-- resuming from the next unprocessed input byte.  The caller is
-- responsible for ensuring @0 <= off@ and @off + len <= SB.length sbs@.
primMapShortByteStringSliceBounded
    :: BP.BoundedPrim Word8 -> Int -> Int -> ShortByteString -> Builder
primMapShortByteStringSliceBounded bp !off !len sbs
    | len <= 0  = mempty
    | otherwise = BI.builder (step off)
  where
    !bound = (BPI.sizeBound bp)
    !sEnd  = off + len

    step :: Int -> BI.BuildStep r -> BI.BuildStep r
    step !i k (BI.BufferRange op0 ope) = go i op0
      where
        go !j !op
          | j >= sEnd = k (BI.BufferRange op ope)
          | op `plusPtr` bound > ope =
              return $ BI.bufferFull bound op (step j k)
          | otherwise = do
              op' <- BPI.runB bp (SB.index sbs j) op
              go (j + 1) op'
