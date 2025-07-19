module Net.DNSBase.Internal.Util
    ( (.=), (<.>), (<$.>)
    , bool, cond
    , compose4
    , ByteArray(..), baToShortByteString, modifyArray
    , sbsToByteArray, sbsToMutableByteArray
    , Down(..), comparing
    , (.|.), (.&.), clearBit, countLeadingZeros, complement, setBit
    , shiftL, shiftR, testBit, unsafeShiftL, unsafeShiftR
    , (<|>), (>=>), forM, forM_, guard, join, mzero, replicateM, unless, void, when
    , lift, ExceptT(..), throwE, catchE, runExceptT, withExceptT
    , ByteString, Builder, ShortByteString(..)
    , Coercible, coerce
    , Int8, Int16, Int32, Int64
    , Word8, Word16, Word32, Word64, word16be, word32be, toBE
    , IP(..), IPv4, IPv6, fromIPv4w, fromIPv6b, fromIPv6w, toIPv4w, toIPv6b, toIPv6w
    , All(..), Sum(..)
    , catMaybes, fromMaybe, isJust, isNothing, listToMaybe, mapMaybe
    , NonEmpty(..)
    , shows', showsP
    , Type, Typeable, (:~:)(..), Proxy(..), cast, teq
    , allocaBytesAligned, castPtr, copyBytes, byteSwap32
    , fillBytes, minusPtr, peek, peekElemOff, plusForeignPtr
    , unsafePerformFPIO
    ) where

import qualified Data.Primitive.ByteArray as A
import qualified Data.ByteString.Short as SB
import Control.Applicative ((<|>))
import Control.Monad ( (>=>), forM, forM_, guard, join, mzero, replicateM )
import Control.Monad ( unless, void, when )
import Control.Monad.ST (ST)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Except (ExceptT(..), throwE, catchE, runExceptT, withExceptT)
import Data.Array.Byte (ByteArray(..), MutableByteArray(..))
import Data.Bits ((.|.), (.&.), clearBit, countLeadingZeros, complement)
import Data.Bits (setBit, shiftL, shiftR, testBit, unsafeShiftL, unsafeShiftR)
import Data.Bool (bool)
import Data.ByteString (ByteString)
import Data.ByteString.Builder (Builder)
import Data.ByteString.Internal (ByteString(..), accursedUnutterablePerformIO)
import Data.ByteString.Short (ShortByteString(SBS))
import Data.Coerce (Coercible, coerce)
import Data.IP (IP(..), IPv4, IPv6)
import Data.IP (fromIPv4w, fromIPv6b, fromIPv6w, toIPv4w, toIPv6b, toIPv6w)
import Data.Int (Int64, Int32, Int16, Int8)
import Data.Kind (Type)
import Data.List.NonEmpty (NonEmpty(..))
import Data.Maybe (catMaybes, fromMaybe, isJust, isNothing, listToMaybe, mapMaybe)
import Data.Monoid (All(..), Sum(..))
import Data.Ord (Down(..), comparing)
import Data.Proxy (Proxy(..))
import Data.Type.Equality ((:~:)(..), testEquality)
import Data.Typeable (Typeable, cast)
import Data.Word (Word8, Word16, Word32, Word64, byteSwap16, byteSwap32)
import Foreign (ForeignPtr, Ptr, allocaBytesAligned, castPtr, copyBytes)
import Foreign (fillBytes, minusPtr, peek, peekElemOff, plusForeignPtr)
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
