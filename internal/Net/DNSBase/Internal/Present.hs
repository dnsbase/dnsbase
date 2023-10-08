{-# LANGUAGE
    MagicHash
  , UnboxedTuples
  #-}
module Net.DNSBase.Internal.Present
    ( -- * Presentable class
      Presentable(..)
    -- ** Builder combinators
    , presentByte
    , presentCharSep
    , presentCharSepLn
    , presentLn
    , presentSep
    , presentSepLn
    , presentSp
    , presentSpLn
    -- *** Newtype for parsing and presenting 64-bit epoch times.
    , Epoch64(..)
    -- ** Build directly to a 'String' or 'ByteString'
    , presentString
    , presentStrict
    -- ** Re-exports from "Data.ByteString.Builder"
    , Builder
    , hPutBuilder
    -- *** 'hPutBuilder' specialised to 'stdout'
    , putBuilder
    ) where

import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Builder.Extra as B
import qualified Data.ByteString.Builder.Prim as P
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Lazy.Char8 as L8
import qualified Data.IP.Builder as IP
import qualified System.IO as IO
import Data.ByteString.Builder (hPutBuilder)
import Data.ByteString.Builder.Prim ((>$<), (>*<))
import Data.String (IsString(..))
import Data.Time.Clock.System (SystemTime(..), utcToSystemTime)
import Data.Time.Format (defaultTimeLocale, parseTimeOrError)

import Net.DNSBase.Internal.Util

-- | Return DNS presentation form, as a lazy ByteString builder, taking a
-- continuation.  Since DNS record presentation form is ASCII, we don't need
-- Unicode strings, and lazy ByteString builders perform one to two orders of
-- magnitude faster.
--
-- Complex builders with nested sub-components are much more efficient when
-- constructed in continuation passing style.
--
class Presentable a where
    -- | Serialise the input value with the given continuation.
    present :: a        -- ^ Value to serialise
            -> Builder  -- ^ Continuation
            -> Builder  -- ^ Final output
    -- | Run the builder immediately, producing a lazy 'L.ByteString' with the
    -- given tail.
    presentLazy :: a -> L.ByteString -> L.ByteString
    presentLazy a k = B.toLazyByteStringWith strat k $ present a mempty
      where
        strat = B.safeStrategy 128 B.smallChunkSize

-- | Append a char, assumed 8-bit only.
instance Presentable Char where
    present = (<>) . B.char8
    {-# INLINE present #-}

-- | Append a string, assumed ASCII.
instance Presentable String where
    present = (<>) . B.string8
    {-# INLINE present #-}

-- | Append a 'ShortByteString' assumed already escaped to not require
-- additional escaping or quoting.
--
instance Presentable ShortByteString where
    present = (<>) . B.shortByteString
    {-# INLINE present #-}

instance Presentable ByteString where
    present = (<>) . B.byteString
    {-# INLINE present #-}

-- Append a decimal Int
instance Presentable Int where
    present = (<>) . B.intDec
    {-# INLINE present #-}

-- Append a decimal Int64
instance Presentable Int64 where
    present = (<>) . B.int64Dec
    {-# INLINE present #-}

-- Append a decimal Int32
instance Presentable Int32 where
    present = (<>) . B.int32Dec
    {-# INLINE present #-}

-- Append a decimal Int16
instance Presentable Int16 where
    present = (<>) . B.int16Dec
    {-# INLINE present #-}

-- Append a decimal Int8
instance Presentable Int8 where
    present = (<>) . B.int8Dec
    {-# INLINE present #-}

-- Append a decimal word8
instance Presentable Word8 where
    present = (<>) . B.word8Dec
    {-# INLINE present #-}

instance Presentable Word16 where
    present = (<>) . B.word16Dec
    {-# INLINE present #-}

instance Presentable Word32 where
    present = (<>) . B.word32Dec
    {-# INLINE present #-}

instance Presentable Word64 where
    present = (<>) . B.word64Dec
    {-# INLINE present #-}

instance Presentable IP where
    present = (<>) . IP.ipBuilder

instance Presentable IPv4 where
    present = (<>) . IP.ipv4Builder

instance Presentable IPv6 where
    present = (<>) . IP.ipv6Builder

presentByte :: Word8 -> Builder -> Builder
presentByte = (<>) . B.word8
{-# INLINE presentByte #-}

presentLn :: Presentable a => a -> Builder -> Builder
presentLn a = present a . presentByte 0x0a
{-# INLINE presentLn #-}

-- | Append with a leading separator
presentSep :: Presentable a => Word8 -> a -> Builder -> Builder
presentSep sep a = presentByte sep . present a
{-# INLINE presentSep #-}

-- | Append with a leading separator and a trailing newline
presentSepLn :: Presentable a => Word8 -> a -> Builder -> Builder
presentSepLn sep a = presentByte sep . presentLn a
{-# INLINE presentSepLn #-}

-- | Append with a leading 'Char' octet separator
presentCharSep :: Presentable a => Char -> a -> Builder -> Builder
presentCharSep sep a = present sep . present a
{-# INLINE presentCharSep #-}

-- | Append with a leading separator and a trailing newline
presentCharSepLn :: Presentable a => Char -> a -> Builder -> Builder
presentCharSepLn sep a = present sep . presentLn a
{-# INLINE presentCharSepLn #-}

-- | Append with a leading space
presentSp :: Presentable a => a -> Builder -> Builder
presentSp = presentSep 0x20
{-# INLINE presentSp #-}

-- | Append with a leading space and a trailing newline
presentSpLn :: Presentable a => a -> Builder -> Builder
presentSpLn a = presentByte 0x20 . presentLn a
{-# INLINE presentSpLn #-}

-- | Immediately construct a strict 'ByteString' from the input followed by
-- the given lazy 'L.ByteString' tail.
presentStrict :: Presentable a => a -> L.ByteString -> ByteString
presentStrict a = L.toStrict . presentLazy a

-- | Immediately construct a 'String' from the input followed by the given
-- tail.
presentString :: Presentable a => a -> String -> String
presentString a k = L8.unpack (presentLazy a mempty) ++ k

-- | Execute the Builder writing output to 'stdout'.  Typically, 'stdout'
-- should be set in 'IO.BinaryMode' with 'IO.BlockBuffering'.  See
-- 'IO.hSetBinaryMode' and 'IO.hSetBuffering' for details.
--
putBuilder :: Builder -> IO ()
putBuilder = hPutBuilder IO.stdout

-- | 64-bit extended representation of 32-bit DNS clock-arithmetic types.
-- The presentation form is as a YYYYMMDDHHMMSS string.
newtype Epoch64 = Epoch64 Int64
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral)

-- | Parse DNSSEC YYYYmmddHHMMSS time format to 'Epoch64' value
instance IsString Epoch64 where
    fromString = coerce . systemSeconds . utcToSystemTime . parseUTC
      where
        parseUTC = parseTimeOrError False defaultTimeLocale "%Y%m%d%H%M%S"

instance Show Epoch64 where
    showsPrec _ e = showChar '"' . presentString e . showChar '"'

instance Presentable Epoch64 where
    -- <http://howardhinnant.github.io/date_algorithms.html>
    -- (years prior 1000 are not supported).
    -- This avoids all the pain of converting epoch time to NominalDiffTime ->
    -- UTCTime -> LocalTime then using formatTime with defaultTimeLocale!
    -- >>> :{
    -- let testVector =
    --         [ ( "19230704085602", -1467299038)
    --         , ( "19331017210945", -1142563815)
    --         , ( "19480919012827", -671668293 )
    --         , ( "19631210171455", -191227505 )
    --         , ( "20060819001740", 1155946660 )
    --         , ( "20180723061122", 1532326282 )
    --         , ( "20281019005024", 1855529424 )
    --         , ( "20751108024632", 3340406792 )
    --         , ( "21240926071415", 4883008455 )
    --         , ( "21270331070215", 4962150135 )
    --         , ( "21371220015305", 5300560385 )
    --         , ( "21680118121052", 6249787852 )
    --         , ( "21811012210032", 6683202032 )
    --         , ( "22060719093224", 7464648744 )
    --         , ( "22100427121648", 7583717808 )
    --         , ( "22530821173957", 8950757997 )
    --         , ( "23010804210243", 10463979763)
    --         , ( "23441111161706", 11829514626)
    --         , ( "23750511175551", 12791843751)
    --         , ( "23860427060801", 13137746881) ]
    --  in (==) <$> map (showTime.snd) <*> map fst $ testVector
    -- :}
    -- True
    --
    present (Epoch64 t) k =
        B.int64Dec year
        <> pad2 mon
        <> pad2 day
        <> pad2 hh
        <> pad2 mm
        <> pad2 ss
        <> k
      where
        (!z0, !s) = t `divMod` 86400
        !z = z0 + 719468
        (!era, !doe) = z `divMod` 146097
        !yoe = (doe - doe `quot` 1460 + doe `quot` 36524
                   - doe `quot` 146096) `quot` 365
        !y = yoe + era * 400
        !doy = doe - (365*yoe + yoe `quot` 4 - yoe `quot` 100)
        !mp = (5*doy + 2) `quot` 153
        !day = doy - (153*mp + 2) `quot` 5 + 1
        !mon = 1 + (mp + 2) `rem` 12
        !year = y + (12 - mon) `quot` 10
        (!hh, (!mm, !ss)) = flip divMod 60 <$> s `divMod` 3600

        pad2 :: Integral a => a -> Builder
        pad2 = P.primBounded w2 . fromIntegral
          where
            w2 = P.condB
                   do (> 9)
                   do P.word8Dec
                   do ((), ) >$< (const 0x30 >$< P.liftFixedToBounded P.word8) >*< P.word8Dec
