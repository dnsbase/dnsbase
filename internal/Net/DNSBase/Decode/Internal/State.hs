{-# LANGUAGE
    AllowAmbiguousTypes
  , OverloadedStrings
  , RecordWildCards
  #-}
module Net.DNSBase.Decode.Internal.State
    (
    -- * DNS message element parser
      SGet
    -- * Internal state accessors
    , getPosition
    , getPacket
    , getChrono
    , getNameComp
    -- ** Deduplication support
    , getLastOwner
    , getLastCname
    , setLastOwner
    , setLastCname
    -- ** Setting a non-default error context
    , setDecodeSection
    , setDecodeTriple
    , setDecodeSource
    , local
    -- * Generic low-level decoders
    , get8
    , get16
    , get32
    , getInt8
    , getInt16
    -- * DNS-specific low-level decoders
    , getIPv4
    , getIPv4Net
    , getIPv6
    , getIPv6Net
    , getDnsTime
    -- * Octet-string decoders
    , skipNBytes
    , getNBytes
    , getShortNByteString
    , getShortByteStringLen8
    , getShortByteStringLen16
    , getUtf8Text
    , getUtf8TextLen8
    , getUtf8TextLen16
    -- * Sequence decoders
    , getVarWidthSequence
    , getFixedWidthSequence
    -- * Decoder sandboxing
    , seekSGet
    , fitSGet
    -- * Decoder failure
    , failSGet
    -- * Decoder driver
    , decodeAtWith
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Short as SB
import qualified Data.ByteString.Unsafe as B
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Data.ByteString.Internal (ByteString(..))

import Net.DNSBase.Decode.Internal.RSE
import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Peer
import Net.DNSBase.Internal.Util

-----------

data SGetEnv = SGetEnv
    { psPacket   :: ByteString
    , psChrono   :: Int64
    , psNameComp :: Bool
    , psSection  :: DnsSection
    , psTriple   :: Maybe DnsTriple
    , psSource   :: Maybe MessageSource
    }

data SGetState = SGetState
    { psOffset    :: Int
    , psLength    :: Int
    , psLastOwner :: Domain
    , psLastCname :: Domain
    }

-- | Minimal non-backtracking Reader + State parser Monad.
type SGet a = RSE DNSError SGetEnv SGetState a

runSGet :: SGet a -> SGetEnv -> SGetState -> Either DNSError (a, SGetState)
runSGet = runRSE

evalSGet :: SGet a -> SGetEnv -> SGetState -> Either DNSError a
evalSGet = evalRSE

failSGet :: String -> SGet a
failSGet msg = do
    SGetEnv { psSection = decodeSection
            , psTriple  = decodeTriple
            , psSource  = decodeSource } <- ask
    throwRSE $ DecodeError DecodeContext {..} msg

-------------

-- | Consumes and returns a 'ByteString' of length @n@ from the buffer
--
-- Fails if this would back-track or over-run.
getNByteString :: Int -> SGet ByteString
getNByteString n | n == 0 = pure B.empty
getNByteString n | n > 0  = do
    s <- get
    when (psLength s < n) do failSGet "requested bytecount exceeds available"
    modify' \t -> t { psOffset = psOffset s + n
                    , psLength = psLength s - n}
    (BS fp _) <- asks psPacket
    pure $! BS (fp `plusForeignPtr` psOffset s) n
getNByteString _ = failSGet "negative bytecount requested"
{-# INLINE getNByteString #-}

-- | Consumes and discards @n@ bytes of input from the buffer
skipNBytes :: Int -> SGet ()
skipNBytes n | n >= 0 = do
    s <- get
    when (psLength s < n) do
        failSGet "requested skip bytecount exceeds available"
    when (n > 0) do
        modify' $ \t -> t { psOffset = psOffset s + n
                          , psLength = psLength s - n }
skipNBytes _ = failSGet "negative skip bytecount requested"
{-# INLINE skipNBytes #-}

-- | Returns the current position relative to the start of the internal buffer
getPosition :: SGet Int
getPosition = gets psOffset
{-# INLINE getPosition #-}

-- | Returns the entire contents of the internal buffer
getPacket :: SGet ByteString
getPacket = asks psPacket
{-# INLINE getPacket #-}

-- | Returns the epoch-relative time passed to 'decodeAtWith'
getChrono :: SGet Int64
getChrono = asks psChrono
{-# INLINE getChrono #-}

-- | Returns whether name (de)compression is applicable to the input buffer.
--
-- Generally true for full DNS messages, and false for data blobs encoded in
-- isolation.
getNameComp :: SGet Bool
getNameComp = asks psNameComp
{-# INLINE getNameComp #-}

getLastOwner, getLastCname :: SGet Domain
setLastOwner, setLastCname :: Domain -> SGet Domain
getLastOwner = gets psLastOwner
getLastCname = gets psLastCname
setLastOwner d = d <$ modify' \ s -> s { psLastOwner = d }
setLastCname d = d <$ modify' \ s -> s { psLastCname = d }
{-# INLINE getLastOwner #-}
{-# INLINE getLastCname #-}
{-# INLINE setLastOwner #-}
{-# INLINE setLastCname #-}

-- | Set message section for error reporting.
setDecodeSection :: DnsSection -> SGetEnv -> SGetEnv
setDecodeSection psSection SGetEnv { psSection = _, ..} = SGetEnv {..}

-- | Set current RRset name, type, class for error reporting.
setDecodeTriple :: DnsTriple -> SGetEnv -> SGetEnv
setDecodeTriple (Just -> psTriple) SGetEnv { psTriple = _, ..} = SGetEnv {..}

-- | Set message source for error reporting.
setDecodeSource :: MessageSource -> SGetEnv -> SGetEnv
setDecodeSource (Just -> psSource) SGetEnv { psSource = _, ..} = SGetEnv {..}

--------------------------------

-- | Consumes one octet and returns it as a 'Word8'
get8 :: SGet Word8
get8 = B.unsafeIndex <$> asks psPacket <*> (gets psOffset <* skipNBytes 1)
{-# INLINE get8 #-}

-- | Load a 16-bit big-endian word.
get16 :: SGet Word16
get16 = word16be <$> getNByteString 2
{-# INLINE get16 #-}

-- | Load a 32-bit big-endian word.
get32 :: SGet Word32
get32 = word32be <$> getNByteString 4
{-# INLINE get32 #-}

-- | Consumes one octet and returns it as an 'Int'
getInt8 :: SGet Int
getInt8 = fromIntegral <$> get8
{-# INLINE getInt8 #-}

-- | Consumes two octets and returns them as an 'Int'
-- computed using network byte order
getInt16 :: SGet Int
getInt16 = fromIntegral <$> get16
{-# INLINE getInt16 #-}

--  Not implemented, risks sign overflow on 32-bit systems.
--
--  -- | Consumes four octets and returns them as an 'Int'
--  -- computed using network byte order
--  getInt32 :: SGet Int
--  getInt32 = fromIntegral <$> get32
--  {-# INLINE getInt32 #-}

----

-- | Reads 4 octets and returns them as an 'IPv4' address
getIPv4 :: SGet IPv4
getIPv4 = toIPv4w <$> get32
{-# INLINE getIPv4 #-}

-- | Reads 16 octets and returns them as an 'IPv6' address
getIPv6 :: SGet IPv6
getIPv6 = toIPv6w <$> ((,,,) <$> get32 <*> get32 <*> get32 <*> get32)
{-# INLINE getIPv6 #-}

-- | Reads up to four octets and returns them as an 'IPv4'
-- address padded as needed with trailing 0x0 bytes.
getIPv4Net :: Int -> SGet IPv4
getIPv4Net n | n >= 0 && n <= 4 =
    getNByteString n >>= \ (BS fp _) -> pure $! unsafePerformFPIO fp \ptr -> do
        allocaBytesAligned 4 4 $ \buf -> do
            fillBytes buf 0 4
            copyBytes buf ptr n
            w <- toBE byteSwap32 <$> peek (castPtr buf)
            pure $ toIPv4w w
getIPv4Net _ = failSGet "invalid IPv4 prefix length"

-- | Reads up to 16 octets and returns them as an 'IPv6' address
-- padded as needed with trailing 0x0 bytes.
getIPv6Net :: Int -> SGet IPv6
getIPv6Net n | n >= 0 && n <= 16 =
    getNByteString n >>= \ (BS fp _) -> pure $! unsafePerformFPIO fp \ptr -> do
        allocaBytesAligned 16 4 $ \buf -> do
            fillBytes buf 0 16
            copyBytes buf ptr n
            w0 <- toBE byteSwap32 <$> peekElemOff (castPtr buf) 0
            w1 <- toBE byteSwap32 <$> peekElemOff (castPtr buf) 1
            w2 <- toBE byteSwap32 <$> peekElemOff (castPtr buf) 2
            w3 <- toBE byteSwap32 <$> peekElemOff (castPtr buf) 3
            pure $ toIPv6w (w0,w1,w2,w3)
getIPv6Net _ = failSGet "invalid IPv6 prefix length"

-- | Converts a 32-bit circle-arithmetic DNS time to an absolute 64-bit DNS
-- timestamp that lies within a 31-bit band of the parser state's reference
-- timestamp.
getDnsTime :: SGet Int64
getDnsTime = dnsTime <$> get32 <*> getChrono
  where
    dnsTime :: Word32 -- ^ DNS circle-arithmetic timestamp
            -> Int64  -- ^ reference epoch time
            -> Int64  -- ^ absolute DNS timestamp
    dnsTime tdns tnow =
        let delta = tdns - fromIntegral tnow
         in if delta > 0x7FFF_FFFF -- tdns is in the past?
               then tnow - (0x1_0000_0000 - fromIntegral delta)
               else tnow + fromIntegral delta
{-# INLINE getDnsTime #-}

----------------------------------------

-- | Consumes and returns @n@ bytes of input from the buffer.
getNBytes :: Int -> SGet [Word8]
getNBytes n = B.unpack <$> getNByteString n
{-# INLINE getNBytes #-}

-- | Decodes a sequence of values with a fixed wire-form byte-width.
getFixedWidthSequence :: Int    -- ^ Number of octets to encode one value
                      -> SGet a -- ^ Decoder for a single value
                      -> Int    -- ^ Total number of octets in the sequence
                      -> SGet [a]
getFixedWidthSequence wdth getOne len@((`quotRem` wdth) -> (cnt, 0)) =
  fitSGet len $ replicateM cnt getOne
getFixedWidthSequence _ _ _ =
  failSGet "sequence length not multiple of element size"
{-# INLINE getFixedWidthSequence #-}

-- | Decodes a sequence of values with a variable wire-form byte-width.
getVarWidthSequence :: SGet a   -- ^ Decoder for a single value
                    -> Int      -- ^ Total number of octets in the sequence
                    -> SGet [a]
getVarWidthSequence getOne = fitSGet <$> id <*> go
  where
    go n | n > 0 = do
      pos0 <- getPosition
      x    <- getOne
      used <- (subtract pos0) <$> getPosition
      (x : ) <$> go (n - used)
    go 0 = pure []
    go _ = failSGet "last sequence element read past limit"
{-# INLINE getVarWidthSequence #-}

-- | Consumes and returns a 'ShortByteString' of length @n@ from the buffer.
getShortNByteString :: Int -> SGet ShortByteString
getShortNByteString n = SB.toShort <$> getNByteString n
{-# INLINE getShortNByteString #-}

-- | Read a ShortByteString whose length is determined by an 8-bit prefix.
getShortByteStringLen8 :: SGet ShortByteString
getShortByteStringLen8 = getInt8 >>= getShortNByteString
{-# INLINE getShortByteStringLen8 #-}

-- | Read a ShortByteString whose length is determined by a 16-bit prefix.
getShortByteStringLen16 :: SGet ShortByteString
getShortByteStringLen16 = getInt16 >>= getShortNByteString
{-# INLINE getShortByteStringLen16 #-}

-- | Read a UTF8-encoded text string of the given length.
getUtf8Text :: Int -> SGet T.Text
getUtf8Text len = T.decodeUtf8' <$> getNByteString len >>= \ case
    Right txt -> pure txt
    Left  err -> failSGet $ show err
{-# INLINE getUtf8Text #-}

-- | Read a UTF8-encoded text string preceded by an explicit 8-bit length.
getUtf8TextLen8 :: SGet T.Text
getUtf8TextLen8 = getInt8 >>= T.decodeUtf8' <.> getNByteString >>= \ case
    Right txt -> pure txt
    Left  err -> failSGet $ show err
{-# INLINE getUtf8TextLen8 #-}

-- | Read a UTF8-encoded text string preceded by an explicit 16-bit length.
getUtf8TextLen16 :: SGet T.Text
getUtf8TextLen16 = getInt16 >>= T.decodeUtf8' <.> getNByteString >>= \ case
    Right txt -> pure txt
    Left  err -> failSGet $ show err
{-# INLINE getUtf8TextLen16 #-}

-- | Seek to an offset less than the current position and run a parser
-- in a sandboxed state. This inequality must be enforced by the caller.
-- The caller's state remains unchanged.
seekSGet :: Word16 -> SGet a -> SGet a
seekSGet pos parser = do
    let off = fromIntegral pos
    len <- B.length <$> getPacket
    when (off > len) do
        -- Caller failed to enforce preconditions!
        failSGet "seek attempt beyond end of buffer"
    env   <- ask
    state <- gets \ s -> s { psOffset = off
                           , psLength = len - off }
    case runSGet parser env state of
        Right (ret, _) -> pure ret
        Left err       -> throwRSE err

-- | Runs a parser on an initial segment of the unread input consumes exactly
-- the specified number of bytes.
fitSGet :: Int -> SGet a -> SGet a
fitSGet len parser | len >= 0 = do
    s <- get
    when (psLength s < len) do
        failSGet "requested skip bytecount exceeds available"
    when (len > 0) do
        modify' $ \t -> t { psOffset = psOffset s + len
                          , psLength = psLength s - len }
    env <- ask
    case runSGet parser env s { psLength = len } of
        Right (ret, t)
            | psLength t == 0 -> pure $! ret
            | otherwise       -> failSGet "element shorter than indicated size"
        Left err -> throwRSE err
fitSGet _ _ = failSGet "negative sanbox buffer size"
{-# INLINE fitSGet #-}

--------------------------

-- | Run a decoder with a given epoch offset over specified input
decodeAtWith :: Int64       -- ^ Current absolute offset from epoch
             -> Bool        -- ^ Support name compression?
             -> SGet a      -- ^ Decoder to run
             -> ByteString  -- ^ Buffer to run decoder over
             -> Either DNSError a
decodeAtWith t nc parser inp =
    evalSGet parser SGetEnv{..} SGetState{..}
  where
    psPacket     = inp
    psChrono     = t
    psNameComp   = nc
    psSection    = DnsNonSection
    psTriple     = Nothing
    psSource     = Nothing
    psOffset     = 0
    psLength     = B.length inp
    psLastOwner  = RootDomain
    psLastCname  = RootDomain
