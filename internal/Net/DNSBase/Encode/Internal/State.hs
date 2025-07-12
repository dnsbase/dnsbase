{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.Encode.Internal.State
    ( EncodeErr(..)
    , SPut
    , buildCompressed
    , encodeCompressed
    , buildVerbatim
    , encodeVerbatim
    , putDomain
    , putWireForm
    , put8
    , put16
    , put32
    , put64
    , putInt8
    , putInt16
    , putInt32
    , putIPv4
    , putIPv6
    , putByteString
    , putByteStringLen8
    , putByteStringLen16
    , putShortByteString
    , putShortByteStringLen8
    , putShortByteStringLen16
    , putUtf8TextLen8
    , putUtf8TextLen16
    , putSizedBuilder
    , putReplicate
    -- 'safe' re-exports of RWST functions
    , passLen
    , failWith
    , setContext
    ) where

import qualified Control.Monad.STE as STE
import qualified Control.Monad.STE.Internal as STE
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Builder.Extra as B
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Short as SB
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Unsafe as T
import Control.Monad.Trans.RWS.CPS ( RWST, evalRWST, ask, get, gets, local
                                   , pass, put, tell )
import GHC.ST as G (ST(..))

import qualified Net.DNSBase.Internal.NameComp as NC
import Net.DNSBase.Internal.Domain
import Net.DNSBase.Encode.Internal.Metric
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Util

----------------------------------------------------------------

stToSTE :: G.ST s a -> STE.STE e s a
stToSTE = coerce

----------------------------------------------------------------

-- | Encoder state, the NCTree (DNS name compression tree) is mutable in the ST
-- monad.
data EncState s = EncState
    { encOffset :: Int
    , encDoNC   :: Bool
    , encNCTree :: NC.NCTree s
    }

-- | Initial encoder state.
encInit :: Bool -- ^ If "True", DNS name compression is enabled
        -> STE.STE e s (EncState s)
encInit donamecomp = EncState 0 donamecomp <$> stToSTE (NC.empty 0)

----------------------------------------------------------------

type EncM s r = RWST r Builder (EncState s) (STE.STE (EncodeErr r) s)

-- | Encode an output packet in the ST monad, with `r` as an optional error
-- context (typically the RData being encoded, when applicable).
type SPut s r = EncM s (Maybe r) ()

type ErrorContext r = (Typeable r, Show r, Eq r)

buildSPut :: ErrorContext r
        => (forall s. SPut s r)
        -> Bool
        -> Either (EncodeErr (Maybe r)) (Int, Builder)
buildSPut m donc = STE.handleSTE id do
    st <- encInit donc
    evalRWST (m >> gets encOffset) Nothing st

-- | Execute the composed 'Builder' endomorphisms to encode a packet of the
-- cumulative length.
runSPut :: ErrorContext r
        => (forall s. SPut s r)
        -> Bool
        -> Either (EncodeErr (Maybe r)) ByteString
runSPut m donc = do
    (len, builder) <- buildSPut m donc
    pure $ LB.toStrict
         $ B.toLazyByteStringWith (strat len) mempty builder
  where
    strat len = B.untrimmedStrategy len len

-- | Perform a stateful encoding with DNS name compression.  The initial error
-- context is "Nothing".  Specific values can be provided during the
-- computation by using 'local'.
buildCompressed :: ErrorContext r
                => (forall s. SPut s r)
                -> Either (EncodeErr (Maybe r)) Builder
buildCompressed m = snd <$> buildSPut m True

-- | Perform a stateful encoding with DNS name compression.  The initial error
-- context is "Nothing".  Specific values can be provided during the
-- computation by using 'local'.
encodeCompressed :: ErrorContext r
                 => (forall s. SPut s r)
                 -> Either (EncodeErr (Maybe r)) ByteString
encodeCompressed m = runSPut m True

-- | Perform a stateful encoding without DNS name compression.  The initial
-- error context is "Nothing".  Specific values can be provided during the
-- computation by using 'local'.
buildVerbatim :: ErrorContext r => (forall s. SPut s r) -> Either (EncodeErr (Maybe r)) Builder
buildVerbatim m = snd <$> buildSPut m False

-- | Perform a stateful encoding without DNS name compression.  The initial
-- error context is "Nothing".  Specific values can be provided during the
-- computation by using 'local'.
encodeVerbatim :: ErrorContext r => (forall s. SPut s r) -> Either (EncodeErr (Maybe r)) ByteString
encodeVerbatim m = runSPut m False

-- | Encode a domain with possible name compression if the entire name fits in
-- the first 16K of the output.
putDomain :: ErrorContext r => Domain -> SPut s r
putDomain domain = do
    EncState{..} <- get
    let !wlen = B.length (wireBytes domain) - 1
    if | wlen > 0 && encDoNC
       , !end <- encOffset + wlen
       , !ls <- revLabels domain
        -> do (!slen, !off) <- lift . stToSTE $ NC.lookup ls encNCTree
              when (end <= MaxPtr) $
                  lift . stToSTE $ NC.insert ls end encNCTree
              putCompressed domain wlen slen off
       | otherwise -> putWireForm domain
  where
    putCompressed !dom !dlen !slen !off
        | slen == 0 = putWireForm dom
        | otherwise = do
              when (slen < dlen) do
                  putByteString $ B.take (dlen - slen) $ wireBytes domain
              put16 $ toEnum $ (MaxPos - MaxPtr) + off

-- | Encode a domain name verbatim, without name compression.
putWireForm :: ErrorContext r => Domain -> SPut s r
putWireForm = encVar (SB.length . shortBytes) (B.shortByteString . shortBytes)
{-# INLINE putWireForm #-}

----------------------------------------------------------------

pattern MaxPos :: Int
pattern MaxPos = 0xffff

pattern MaxPtr :: Int
pattern MaxPtr = 0x3fff

{-# INLINE addPos #-}
addPos :: ErrorContext r => Int -> SPut s r
addPos n = do
    !s@EncState{ encOffset = pos } <- get
    let !pos' = pos + n
    when (n > MaxPos || pos' > MaxPos) do
        ask >>= lift . STE.throwSTE . EncodeTooLong
    put $! s { encOffset = pos' }

{-# INLINE encFix #-}
encFix :: ErrorContext r => Int -> (a -> Builder) -> a -> SPut s r
encFix size enc a = addPos size >> tell (enc a)

{-# INLINE encVar #-}
encVar :: ErrorContext r => (a -> Int) -> (a -> Builder) -> a -> SPut s r
encVar getSize enc a = encFix (getSize a) enc a

----------------------------------------------------------------

{-# INLINE put8 #-}
put8 :: ErrorContext r => Word8 -> SPut s r
put8 = encFix 1 B.word8

{-# INLINE put16 #-}
put16 :: ErrorContext r => Word16 -> SPut s r
put16 = encFix 2 B.word16BE

{-# INLINE put32 #-}
put32 :: ErrorContext r => Word32 -> SPut s r
put32 = encFix 4 B.word32BE

{-# INLINE put64 #-}
put64 :: ErrorContext r => Word64 -> SPut s r
put64 = encFix 8 B.word64BE

{-# INLINE putInt8 #-}
putInt8 :: ErrorContext r => Int -> SPut s r
putInt8 = encFix 1 (B.int8 . fromIntegral)

{-# INLINE putInt16 #-}
putInt16 :: ErrorContext r => Int -> SPut s r
putInt16 = encFix 2 (B.int16BE . fromIntegral)

{-# INLINE putInt32 #-}
putInt32 :: ErrorContext r => Int -> SPut s r
putInt32 = encFix 4 (B.int32BE . fromIntegral)

{-# INLINE putIPv4 #-}
putIPv4 :: ErrorContext r => IPv4 -> SPut s r
putIPv4 = put32 . fromIPv4w

{-# INLINE putIPv6 #-}
putIPv6 :: ErrorContext r => IPv6 -> SPut s r
putIPv6 ip6 =
    putSizedBuilder $! mbWord32 w0
                    <> mbWord32 w1
                    <> mbWord32 w2
                    <> mbWord32 w3
  where
    (w0, w1, w2, w3) = fromIPv6w ip6

putByteString :: ErrorContext r => ByteString -> SPut s r
putByteString b =
    unless (B.null b) $ encVar B.length B.byteString b

putShortByteString :: ErrorContext r => ShortByteString -> SPut s r
putShortByteString b =
    unless (SB.null b) $ encVar SB.length B.shortByteString b

putByteStringLen8 :: ErrorContext r => ByteString -> SPut s r
putByteStringLen8 bs@(B.length -> len) | len <= 0xff = do
    addPos (len + 1)
    tell $ B.word8 (iw8 len) <> B.byteString bs
putByteStringLen8 _ =
    failWith EncodeTooLong

putShortByteStringLen8 :: ErrorContext r => ShortByteString -> SPut s r
putShortByteStringLen8 bs@(SB.length -> len) | len <= 0xff = do
    addPos $ len + 1
    tell $ B.word8 (iw8 len) <> B.shortByteString bs
putShortByteStringLen8 _ = failWith EncodeTooLong

putByteStringLen16 :: ErrorContext r => ByteString -> SPut s r
putByteStringLen16 bs@(B.length -> len) | len <= 0xffff = do
    addPos $ len + 2
    tell $ B.word16BE (iw16 len) <> B.byteString bs
putByteStringLen16 _ = failWith EncodeTooLong

putShortByteStringLen16 :: ErrorContext r => ShortByteString -> SPut s r
putShortByteStringLen16 bs@(SB.length -> len) | len <= 0xffff = do
    addPos $ len + 2
    tell $ B.word16BE (iw16 len) <> B.shortByteString bs
putShortByteStringLen16 _ = failWith EncodeTooLong

putUtf8TextLen8 :: ErrorContext r => T.Text -> SPut s r
putUtf8TextLen8 t@(T.lengthWord8-> len) | len <= 0xff = do
    addPos $ len + 1
    tell $ B.word8 (iw8 len) <> T.encodeUtf8Builder t
putUtf8TextLen8 _ = failWith EncodeTooLong

putUtf8TextLen16 :: ErrorContext r => T.Text -> SPut s r
putUtf8TextLen16 t@(T.lengthWord8-> len) | len <= 0xffff = do
    addPos $ len + 2
    tell $ B.word16BE (iw16 len) <> T.encodeUtf8Builder t
putUtf8TextLen16 _ = failWith EncodeTooLong

{-# INLINE iw8 #-}
iw8 :: Int -> Word8
iw8 = fromIntegral

{-# INLINE iw16 #-}
iw16 :: Int -> Word16
iw16 = fromIntegral


putReplicate :: ErrorContext r => Word8 -> Word8 -> SPut s r
putReplicate n w =
    encFix (fromEnum n) B.lazyByteString $
        LB.replicate (fromIntegral n) w

{-# INLINE putSizedBuilder #-}
putSizedBuilder :: ErrorContext r => SizedBuilder -> SPut s r
putSizedBuilder (SizedBuilder len b) = addPos len >> tell b
putSizedBuilder _                    = failWith EncodeTooLong

------------------------------------------

passLen :: ErrorContext r => EncM s (Maybe r) a -> EncM s (Maybe r) a
passLen m = pass $ do
        pos <- addPos 2 >> gets encOffset
        x <- m
        len <- subtract pos <$> gets encOffset
        return (x, prependLen len)

prependLen :: Int -> B.Builder -> B.Builder
prependLen = mappend . B.word16BE . fromIntegral

failWith :: ErrorContext r => (forall a. ErrorContext a => a -> EncodeErr a) -> SPut s r
failWith f = ask >>= lift . STE.throwSTE . f

{-# INLINE setContext #-}
setContext :: ErrorContext r => r -> EncM s (Maybe r) a -> EncM s (Maybe r) a
setContext r = local (const $ Just r)
