-- |
-- Module      : Net.DNSBase.Encode.Internal.State
-- Description : Encoder state monad and wire-format primitives
-- Copyright   : (c) IIJ Innovation Institute Inc., 2009
--               (c) Viktor Dukhovni, 2020-2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}

module Net.DNSBase.Encode.Internal.State
    ( EncodeErr(..)
    , ErrorContext
    , SPut, SPutM, localSPut
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
    , putIPv4
    , putIPv6
    , putByteString
    , putByteStringLen8
    , putByteStringLen16
    , putShortByteString
    , putShortByteStringLen8
    , putShortByteStringLen16
    , putUtf8Text
    , putUtf8TextLen8
    , putUtf8TextLen16
    , putSizedBuilder
    , putReplicate
    -- Encoder state mutation
    , passLen
    , failWith
    , setContext
    , encoderOffset
    , setQNameHint
    , setLastOwnerHint
    ) where

import qualified Control.Monad.Trans.RWS.CPS
        as R ( RWST, evalRWST, ask, get, gets, local
             , pass, put, tell )
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

-- | Encoder state.  The QNAME and last-owner hints use 'RootDomain'
-- as the unset sentinel.
data EncState s = EncState
    { encOffset       :: Int
    , encDoNC         :: Bool
    , encNCTree       :: NC.NCMap s
    , encQName        :: Domain
    , encQNameOff     :: Int
    , encLastOwner    :: Domain
    , encLastOwnerOff :: Int
    }

-- | Initial encoder state.
encInit :: Bool -- ^ If "True", DNS name compression is enabled
        -> STE.STE e s (EncState s)
encInit donamecomp = do
    nc <- stToSTE NC.empty
    pure $ EncState 0 donamecomp nc RootDomain 0 RootDomain 0

----------------------------------------------------------------

type ErrorContext r = (Typeable r, Show r, Eq r)

buildSPut :: ErrorContext r
        => (forall s. SPut s r)
        -> Bool
        -> Either (EncodeErr (Maybe r)) (Int, Builder)
buildSPut m donc = STE.handleSTE id do
    st <- encInit donc
    evalSPutM (m >> gets encOffset) Nothing st

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
-- computation by using 'localSPut'.
buildCompressed :: ErrorContext r
                => (forall s. SPut s r)
                -> Either (EncodeErr (Maybe r)) Builder
buildCompressed m = snd <$> buildSPut m True

-- | Perform a stateful encoding with DNS name compression.  The initial error
-- context is "Nothing".  Specific values can be provided during the
-- computation by using 'localSPut'.
encodeCompressed :: ErrorContext r
                 => (forall s. SPut s r)
                 -> Either (EncodeErr (Maybe r)) ByteString
encodeCompressed m = runSPut m True

-- | Perform a stateful encoding without DNS name compression.  The initial
-- error context is "Nothing".  Specific values can be provided during the
-- computation by using 'localSPut'.
buildVerbatim :: ErrorContext r
              => (forall s. SPut s r)
              -> Either (EncodeErr (Maybe r)) Builder
buildVerbatim m = snd <$> buildSPut m False

-- | Perform a stateful encoding without DNS name compression.  The initial
-- error context is "Nothing".  Specific values can be provided during the
-- computation by using 'localSPut'.
encodeVerbatim :: ErrorContext r
               => (forall s. SPut s r)
               -> Either (EncodeErr (Maybe r)) ByteString
encodeVerbatim m = runSPut m False

-- | Encode a domain with possible name compression if the entire name fits in
-- the first 16K of the output.
putDomain :: ErrorContext r => Domain -> SPut s r
putDomain domain = do
    EncState{..} <- get
    let !sb   = shortBytes domain
        !wlen = SB.length sb - 1
    if wlen > 0 && encDoNC
        then case tryHintMatch domain encQName encQNameOff
                               encLastOwner encLastOwnerOff of
            Just ptr -> put16 ptr
            Nothing  -> do
                m <- liftSPut . stToSTE $
                         NC.lookupAndRegister sb encOffset encNCTree
                case m of
                    Nothing      -> putWireForm domain
                    Just (hb, p) -> do
                        putShortByteStringPrefix hb sb
                        put16 p
        else putWireForm domain

-- QNAME is checked before the last-owner hint: its offset always
-- points at verbatim bytes, whereas the last-owner offset may point
-- at a head-bytes-plus-pointer emission, so preferring QNAME keeps
-- pointer chains one hop shorter when both hints match.
tryHintMatch
    :: Domain -> Domain -> Int -> Domain -> Int -> Maybe Word16
tryHintMatch dom qn qOff lo loOff
    | qn == dom = Just (mkPtr qOff)
    | lo == dom = Just (mkPtr loOff)
    | otherwise = Nothing
  where
    mkPtr off = fromIntegral (0xC000 .|. off)
{-# INLINE tryHintMatch #-}

-- | Record the QNAME compression hint.
setQNameHint :: ErrorContext r => Domain -> Int -> SPut s r
setQNameHint !dom !off = do
    s <- get
    put $! s { encQName = dom, encQNameOff = off }

-- | Record the last-RR-owner compression hint.  The offset is
-- updated only when the owner changes, so consecutive RRs sharing
-- the same owner all point at the first emission rather than
-- chaining through each other.
setLastOwnerHint :: ErrorContext r => Domain -> Int -> SPut s r
setLastOwnerHint !dom !off = do
    s <- get
    when (encLastOwner s /= dom) $
        put $! s { encLastOwner = dom, encLastOwnerOff = off }

-- | The encoder offset at which the next emitted byte will land.
encoderOffset :: SPutM s r Int
encoderOffset = gets encOffset
{-# INLINE encoderOffset #-}

-- | Encode a domain name verbatim, without name compression.
putWireForm :: ErrorContext r => Domain -> SPut s r
putWireForm = encVar (SB.length . shortBytes) (B.shortByteString . shortBytes)
{-# INLINE putWireForm #-}

----------------------------------------------------------------

pattern MaxPos :: Int
pattern MaxPos = 0xffff

{-# INLINE addPos #-}
addPos :: ErrorContext r => Int -> SPut s r
addPos n = do
    !s@EncState{ encOffset = pos } <- get
    let !pos' = pos + n
    when (n > MaxPos || pos' > MaxPos) do
        ask >>= liftSPut . STE.throwSTE . EncodeTooLong
    put $! s { encOffset = pos' }

{-# INLINE encFix #-}
encFix :: ErrorContext r => Int -> (a -> Builder) -> a -> SPut s r
encFix size enc a = addPos size >> tell (enc a)

{-# INLINE encVar #-}
encVar :: ErrorContext r => (a -> Int) -> (a -> Builder) -> a -> SPut s r
encVar getSize enc a = encFix (getSize a) enc a

----------------------------------------------------------------

-- | Write a single octet.
put8 :: ErrorContext r => Word8 -> SPut s r
put8 = encFix 1 B.word8
{-# INLINE put8 #-}

-- | Write a big-endian 16-bit word.
put16 :: ErrorContext r => Word16 -> SPut s r
put16 = encFix 2 B.word16BE
{-# INLINE put16 #-}

-- | Write a big-endian 32-bit word.
put32 :: ErrorContext r => Word32 -> SPut s r
put32 = encFix 4 B.word32BE
{-# INLINE put32 #-}

-- | Write a big-endian 64-bit word.
put64 :: ErrorContext r => Word64 -> SPut s r
put64 = encFix 8 B.word64BE
{-# INLINE put64 #-}

-- | Write the four octets of an IPv4 address in network order.
putIPv4 :: ErrorContext r => IPv4 -> SPut s r
putIPv4 = put32 . fromIPv4w
{-# INLINE putIPv4 #-}

-- | Write the sixteen octets of an IPv6 address in network order.
putIPv6 :: ErrorContext r => IPv6 -> SPut s r
putIPv6 ip6 =
    putSizedBuilder $! mbWord32 w0
                    <> mbWord32 w1
                    <> mbWord32 w2
                    <> mbWord32 w3
  where
    (w0, w1, w2, w3) = fromIPv6w ip6
{-# INLINE putIPv6 #-}

-- | Write the bytes of a 'ByteString' verbatim, with no length prefix.
putByteString :: ErrorContext r => ByteString -> SPut s r
putByteString b =
    unless (B.null b) $ encVar B.length B.byteString b

-- | Write the bytes of a 'ShortByteString' verbatim, with no length prefix.
putShortByteString :: ErrorContext r => ShortByteString -> SPut s r
putShortByteString b =
    unless (SB.null b) $ encVar SB.length B.shortByteString b

-- | Write the first @n@ bytes of a 'ShortByteString' verbatim.
putShortByteStringPrefix :: ErrorContext r => Int -> ShortByteString -> SPut s r
putShortByteStringPrefix !n !sbs
    | n > 0  = addPos n >> tell (shortByteStringSliceB 0 n sbs)
    | n == 0 = pure ()
    | otherwise = failWith CantEncode -- should never happen

-- | Write a DNS /character-string/: an 8-bit length prefix followed
-- by the bytes.  Fails with 'EncodeTooLong' if the input exceeds 255 bytes.
putByteStringLen8 :: ErrorContext r => ByteString -> SPut s r
putByteStringLen8 bs@(B.length -> len) | len <= 0xff = do
    addPos (len + 1)
    tell $ B.word8 (iw8 len) <> B.byteString bs
putByteStringLen8 _ =
    failWith EncodeTooLong

-- | 'ShortByteString' counterpart of 'putByteStringLen8'.
putShortByteStringLen8 :: ErrorContext r => ShortByteString -> SPut s r
putShortByteStringLen8 bs@(SB.length -> len) | len <= 0xff = do
    addPos $ len + 1
    tell $ B.word8 (iw8 len) <> B.shortByteString bs
putShortByteStringLen8 _ = failWith EncodeTooLong

-- | Write a 16-bit-length-prefixed 'ByteString'.  Fails with
-- 'EncodeTooLong' if the input exceeds 65535 bytes.
putByteStringLen16 :: ErrorContext r => ByteString -> SPut s r
putByteStringLen16 bs@(B.length -> len) | len <= 0xffff = do
    addPos $ len + 2
    tell $ B.word16BE (iw16 len) <> B.byteString bs
putByteStringLen16 _ = failWith EncodeTooLong

-- | 'ShortByteString' counterpart of 'putByteStringLen16'.
putShortByteStringLen16 :: ErrorContext r => ShortByteString -> SPut s r
putShortByteStringLen16 bs@(SB.length -> len) | len <= 0xffff = do
    addPos $ len + 2
    tell $ B.word16BE (iw16 len) <> B.shortByteString bs
putShortByteStringLen16 _ = failWith EncodeTooLong

-- | Write the UTF-8 encoding of a 'Text' verbatim, with no
-- length prefix.
putUtf8Text :: ErrorContext r => Text -> SPut s r
putUtf8Text t =
    unless (T.null t) $ encVar T.lengthWord8 T.encodeUtf8Builder t

-- | Write a UTF-8-encoded 'Text' with an 8-bit length prefix
-- (length in /bytes/, not codepoints).  Fails with 'EncodeTooLong'
-- if the UTF-8 encoding exceeds 255 bytes.
putUtf8TextLen8 :: ErrorContext r => Text -> SPut s r
putUtf8TextLen8 t@(T.lengthWord8-> len) | len <= 0xff = do
    addPos $ len + 1
    tell $ B.word8 (iw8 len) <> T.encodeUtf8Builder t
putUtf8TextLen8 _ = failWith EncodeTooLong

-- | Write a UTF-8-encoded 'Text' with a 16-bit length prefix
-- (length in /bytes/).  Fails with 'EncodeTooLong' if the UTF-8
-- encoding exceeds 65535 bytes.
putUtf8TextLen16 :: ErrorContext r => Text -> SPut s r
putUtf8TextLen16 t@(T.lengthWord8-> len) | len <= 0xffff = do
    addPos $ len + 2
    tell $ B.word16BE (iw16 len) <> T.encodeUtf8Builder t
putUtf8TextLen16 _ = failWith EncodeTooLong

iw8 :: Int -> Word8
iw8 = fromIntegral
{-# INLINE iw8 #-}

iw16 :: Int -> Word16
iw16 = fromIntegral
{-# INLINE iw16 #-}

-- | Write @n@ copies of the byte @w@ (used for fixed-width
-- zero-padded fields).
putReplicate :: ErrorContext r => Word8 -> Word8 -> SPut s r
putReplicate n w =
    encFix (fromEnum n) B.lazyByteString $
        LB.replicate (fromIntegral n) w

-- | Write a length-tracked 'SizedBuilder' verbatim, advancing the
-- encoder offset by the builder's recorded length.  Fails with
-- 'EncodeTooLong' when the builder itself carries the overflow
-- sentinel.
putSizedBuilder :: ErrorContext r => SizedBuilder -> SPut s r
putSizedBuilder (SizedBuilder len b) = addPos len >> tell b
putSizedBuilder _                    = failWith EncodeTooLong
{-# INLINE putSizedBuilder #-}

------------------------------------------

-- | Wrap a writer with an outer 16-bit length prefix that is
-- computed automatically from the writer's output.  Used for
-- @RDLENGTH@ and the various length-prefixed sub-fields of RR
-- data (SVCB option values, EDNS option values, and so on).
passLen :: ErrorContext r => SPutM s r a -> SPutM s r a
passLen m = pass $ do
        pos <- addPos 2 >> gets encOffset
        x <- m
        len <- subtract pos <$> gets encOffset
        return (x, prependLen len)

prependLen :: Int -> B.Builder -> B.Builder
prependLen = mappend . B.word16BE . fromIntegral

-- | Abort the encoder with the given error, attaching the current
-- 'ErrorContext' from the reader environment.  Used by individual
-- writers when an out-of-range or otherwise invalid value cannot
-- be serialised.
failWith :: ErrorContext r => (forall a. ErrorContext a => a -> EncodeErr a) -> SPut s r
failWith f = ask >>= liftSPut . STE.throwSTE . f

-- | Run a sub-encoder with the given context value installed, so
-- that any 'failWith' inside reports its error against that
-- context.  Used to label sections of the encode (RR header, RR
-- data, EDNS option, ...) so that error messages identify which
-- field went wrong.
setContext :: ErrorContext r => r -> SPutM s r a -> SPutM s r a
setContext r = localSPut (const $ Just r)
{-# INLINE setContext #-}

----------------------------------------------------------------

type BaseM s r = STE.STE (EncodeErr (Maybe r)) s
type RWST s r = R.RWST (Maybe r) Builder (EncState s) (BaseM s r)

-- | Encode an output packet in the ST monad, with @r@ as an
-- optional error context (typically the RData being encoded, when
-- applicable).
type SPut s r = SPutM s r ()

-- | The underlying SPut monad
newtype SPutM s r a = SPutM { _unSPutM :: RWST s r a }

instance Functor (SPutM s r) where
    fmap :: forall a b. (a -> b) -> SPutM s r a -> SPutM s r b
    fmap = coerce (fmap :: (a -> b) -> RWST s r a -> RWST s r b)
    {-# INLINE fmap #-}

    (<$) :: forall a b. a -> SPutM s r b -> SPutM s r a
    (<$) = coerce ((<$) :: a -> RWST s r b -> RWST s r a)
    {-# INLINE (<$) #-}

instance Applicative (SPutM s r) where
    pure :: forall a. a -> SPutM s r a
    pure = coerce (pure :: a -> RWST s r a)
    {-# INLINE pure #-}

    liftA2 :: forall a b c. (a -> b -> c) -> SPutM s r a -> SPutM s r b -> SPutM s r c
    liftA2 = coerce (liftA2 :: (a -> b -> c) -> RWST s r a -> RWST s r b -> RWST s r c)
    {-# INLINE liftA2 #-}

    (<*>) :: forall a b. SPutM s r (a -> b) -> SPutM s r a -> SPutM s r b
    (<*>) = coerce ((<*>) :: RWST s r (a -> b) -> RWST s r a -> RWST s r b)
    {-# INLINE (<*>) #-}

    (*>) :: forall a b. SPutM s r a -> SPutM s r b -> SPutM s r b
    (*>) = coerce ((*>) :: RWST s r a -> RWST s r b -> RWST s r b)
    {-# INLINE (*>) #-}

    (<*) :: forall a b. SPutM s r a -> SPutM s r b -> SPutM s r a
    (<*) = coerce ((<*) :: RWST s r a -> RWST s r b -> RWST s r a)
    {-# INLINE (<*) #-}

instance Monad (SPutM s r) where
    (>>=) :: forall a b. SPutM s r a -> (a -> SPutM s r b) -> SPutM s r b
    (>>=) = coerce ((>>=) :: RWST s r a -> (a -> RWST s r b) -> RWST s r b)
    {-# INLINE (>>=) #-}

evalSPutM :: forall s r a. (forall t. SPutM t r a) -> (Maybe r) -> (EncState s) -> BaseM s r (a, Builder)
evalSPutM m = coerce (R.evalRWST (coerce m :: (forall t. RWST t r a)) :: Maybe r -> EncState s -> BaseM s r (a, Builder))
{-# INLINE evalSPutM #-}

liftSPut :: forall s r a. BaseM s r a -> SPutM s r a
liftSPut = coerce (lift :: BaseM s r a -> RWST s r a)

ask :: forall s r. SPutM s r (Maybe r)
ask = coerce (R.ask :: RWST s r (Maybe r))
{-# INLINE ask #-}

get :: forall s r. SPutM s r (EncState s)
get = coerce (R.get :: RWST s r (EncState s))
{-# INLINE get #-}

gets :: forall s r a. (EncState s -> a) -> SPutM s r a
gets = coerce (R.gets :: (EncState s -> a) -> RWST s r a)
{-# INLINE gets #-}

-- | Run the encoder with a modified context
localSPut :: forall s r a. (Maybe r -> Maybe r) -> SPutM s r a -> SPutM s r a
localSPut = coerce (R.local :: (Maybe r -> Maybe r) -> RWST s r a -> RWST s r a)
{-# INLINE localSPut #-}

pass :: forall s r a. SPutM s r (a, Builder -> Builder) -> SPutM s r a
pass = coerce (R.pass :: RWST s r (a, Builder -> Builder) -> RWST s r a)
{-# INLINE pass #-}

put :: forall s r. EncState s -> SPutM s r ()
put = coerce (R.put :: EncState s -> RWST s r ())
{-# INLINE put #-}

tell :: forall s r. Builder -> SPutM s r ()
tell = coerce (R.tell :: Builder -> RWST s r ())
{-# INLINE tell #-}
