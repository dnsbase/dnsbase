module Net.DNSBase.Decode.Internal.Domain
    ( getDomain
    , getDomainNC
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as B

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.Util

-- | Wire form length limit, sans final empty root label.
maxWireLen :: Int
maxWireLen = 255

-- | Parse a wire-form domain with \"No Compression\" (i.e. treat pointer labels
--   as invalid)
--
-- When defining the decoders for newly standardized RData types, it is
-- generally required to use this function to decode transparent domain fields,
-- as name compression is explicitly forbidden for domain fields of future RData
-- types (see 'getDomain' for reference)
getDomainNC :: SGet Domain
getDomainNC = do
    (_, bldr) <- getDomain' False =<< getPosition
    case buildDomain (Just bldr) of
        Just dom -> pure dom
        Nothing  -> failSGet "Internal error"

-- | Parse a wire-form domain with name compression (pointer labels) allowed
--
-- This function should only be used when decoding the owner name of resource
-- records, as well as for fields of the initial set of RData types defined in
-- [RFC 1035](https://tools.ietf.org/html/rfc1035) and several others listed in
-- section 4 of [RFC 3597](https://tools.ietf.org/html/rfc3597#section-4),
-- which also states that future RData types MUST NOT use name compression
getDomain :: SGet Domain
getDomain = do
    -- No name (de)compression if the input is only a message fragment.
    nc <- getNameComp
    (_, bldr) <- getDomain' nc =<< getPosition
    case buildDomain (Just bldr) of
        Just dom -> pure dom
        Nothing  -> failSGet "Internal error"

-- | First octet of a label determines the interpretation of the rest of the label;
--   11XX_XXXX indicates a 14-bit compression pointer composed of the low 6 bits of
--   that octet and the entirety of the next octet, while 00XX_XXXX is used for a
--   standard label to encode its length (<=63). 01XX_XXXX was proposed for extended
--   labels but remains experimental, and 10XX_XXXX is presently undefined. Latest
--   status can be found in
--   [IANA registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10)
getDomain' :: Bool -> Int -> SGet (Int, B.Builder)
getDomain' allowPtr start = do
    vl <- get8
    if | vl == 0 -> do
            end <- getPosition
            -- Including the root label length byte
            getSlice start (end+1)
       | vl <= 63 -> do
            let len = fromIntegral vl
            skipNBytes len
            getDomain' allowPtr start
       | vl >= 0b1100_0000 -> do
            unless allowPtr $ failSGet "domain name compression not allowed in current context"
            end <- getPosition
            (plen, prefix) <- getSlice start end
            vl' <- get8
            let offset :: Word16
                offset = (fromIntegral (vl .&. 0x3f) `shiftL` 8) .|. (fromIntegral vl')
            when (fromIntegral offset >= start) $ failSGet "invalid compression pointer"
            (slen, suffix) <- getPtr offset
            let len = plen + slen
            when (len > maxWireLen) do
                failSGet "domain name too long"
            return $ (len, prefix <> suffix)
       | otherwise -> failSGet "unsupported label type"
  where
    getPtr :: Word16 -> SGet (Int, B.Builder)
    getPtr off = seekSGet off $ getPosition >>= getDomain' allowPtr

    -- get a bytestring slice from position i to position j-1
    getSlice :: Int -> Int -> SGet (Int, B.Builder)
    getSlice off ((subtract (off + 1)) -> len)
       | len < 0          = failSGet "negative-length domain name slice"
       | len > maxWireLen = failSGet "domain name too long"
       | otherwise = do
          buf <- getPacket
          let slice = B.take len $ B.drop off buf
          return $ (len, B.byteString slice)
