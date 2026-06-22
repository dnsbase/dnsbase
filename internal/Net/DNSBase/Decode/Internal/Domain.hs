-- |
-- Module      : Net.DNSBase.Decode.Internal.Domain
-- Description : TBD
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
module Net.DNSBase.Decode.Internal.Domain
    ( getDomain
    , getDomainNC
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Primitive.ByteArray as A
import Control.Monad.ST (ST, runST)
import Data.ByteString.Internal (ByteString(..))
import Data.Primitive.ByteArray (MutableByteArray)

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.Util

-- | Wire-form length limit, including the terminal empty root label.
maxWireLen :: Int
maxWireLen = 255

-- | Initial allocation for the output buffer.  Most names fit, so
-- typical decodes avoid resizing; the few that exceed it grow by
-- @cap + cap \`shiftR\` 1@ (1.5x) up to 'maxWireLen'.
initCap :: Int
initCap = 32

-- | Parse a wire-form domain with \"No Compression\" (i.e. treat pointer
-- labels as invalid).
--
-- When defining the decoders for newly standardized RData types, it is
-- generally required to use this function to decode transparent domain
-- fields, as name compression is explicitly forbidden for domain fields
-- of future RData types (see 'getDomain' for reference)
getDomainNC :: SGet Domain
getDomainNC = decodeAt False

-- | Parse a wire-form domain with name compression (pointer labels)
-- allowed.
--
-- This function should only be used when decoding the owner name of
-- resource records, as well as for fields of the initial set of RData
-- types defined in [RFC 1035](https://tools.ietf.org/html/rfc1035) and
-- several others listed in section 4 of
-- [RFC 3597](https://tools.ietf.org/html/rfc3597#section-4), which also
-- states that future RData types MUST NOT use name compression.
getDomain :: SGet Domain
getDomain = getNameComp >>= decodeAt

-- The shared body of 'getDomain' and 'getDomainNC'.  Snapshots the
-- input packet and the SGet cursor, runs the pointer-following walk in
-- 'ST' over a growable 'MutableByteArray', and advances the SGet
-- cursor by however many bytes were consumed at the starting position
-- (the prefix labels plus either the terminal NUL byte or the 2-byte
-- pointer label that ended the inline portion).
decodeAt :: Bool -> SGet Domain
decodeAt allowPtr = do
    pkt   <- getPacket
    start <- getPosition
    case runST (decodeDomain allowPtr pkt start) of
        Right (consumed, dom) -> dom <$ skipNBytes consumed
        Left  msg             -> failSGet msg

-- The wire-form first octet of a label determines the interpretation
-- of the rest of the label.  @11XX_XXXX@ indicates a 14-bit compression
-- pointer composed of the low 6 bits of that octet and the entirety of
-- the next octet, while @00XX_XXXX@ encodes the length (<=63) of a
-- standard label.  @01XX_XXXX@ was proposed for extended labels but
-- remains experimental, and @10XX_XXXX@ is presently undefined.
-- Current status is in the
-- [IANA registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10).
--
-- The walk reads labels at @pos@ from the packet, copying their wire
-- bytes (including each leading length byte) into the growable output
-- buffer.  A pointer label switches reading to its target offset
-- without writing anything itself; the @firstPtr@ position remembers
-- the absolute offset of the /first/ pointer encountered, so the SGet
-- cursor advance at the end can charge the caller for the prefix plus
-- the 2-byte pointer label, not for any bytes read via the pointer.
--
-- Pointer cycles are prevented by the strict-decreasing @minPtr@
-- invariant: each pointer target must be strictly less than the
-- previous one (initially the starting offset).  Since pointer offsets
-- are non-negative and bounded, the chain terminates.
decodeDomain :: forall s. Bool -> ByteString -> Int
             -> ST s (Either String (Int, Domain))
decodeDomain allowPtr pkt@(BS fp _) !start = do
    buf <- A.newByteArray initCap
    runExceptT $ walk start start initCap buf 0 Nothing
  where
    !pktLen = B.length pkt

    walk :: Int                     -- ^ current read offset in packet
         -> Int                     -- ^ strict-decreasing pointer bound
         -> Int                     -- ^ current buffer capacity
         -> MutableByteArray s      -- ^ output buffer
         -> Int                     -- ^ current write position in buffer
         -> Maybe Int               -- ^ packet offset of first pointer, if any
         -> ExceptT String (ST s) (Int, Domain)
    walk !pos !minPtr !cap !buf !cursor !firstPtr = do
        when (pos >= pktLen) $
            throwE "domain name overruns message"
        let !vl = BU.unsafeIndex pkt pos
        if | vl == 0 -> do
               -- Terminal root label: write the NUL byte and freeze.
               sbs <- lift do
                   (buf', _) <- ensureCap buf cap cursor 1
                   A.writeByteArray @Word8 buf' cursor 0
                   unsafeMBAToSBS buf' (cursor + 1)
               let !consumed = case firstPtr of
                       Just p  -> p - start + 2
                       Nothing -> pos - start + 1
               pure (consumed, Domain_ sbs)
           | vl <= 63 -> do
               -- Inline label: copy its length byte plus content bytes.
               -- The @>=@ in the wire-length check reserves space for
               -- the terminal NUL the name will eventually need.
               let !labLen = fromIntegral vl
                   !need   = 1 + labLen
               when (cursor + need >= maxWireLen) $
                   throwE "domain name too long"
               when (pos + need > pktLen) $
                   throwE "label extends past end of message"
               (buf', cap') <- lift $ ensureCap buf cap cursor need
               lift $ copyFpToMBA (fp `plusForeignPtr` pos) buf' cursor need
               walk (pos + need) minPtr cap' buf' (cursor + need) firstPtr
           | vl >= 0b1100_0000 -> do
               -- Compression pointer: jump to the target, with the
               -- target offset constrained to be strictly less than
               -- the previous bound to rule out cycles.
               unless allowPtr $
                   throwE "domain name compression not allowed in current context"
               when (pos + 2 > pktLen) $
                   throwE "compression pointer extends past end of message"
               let !vl' = BU.unsafeIndex pkt (pos + 1)
                   !off = (fromIntegral (vl .&. 0x3f) `shiftL` 8)
                          .|. fromIntegral vl'
               when (off >= minPtr) $ throwE "invalid compression pointer"
               let !firstPtr' = case firstPtr of
                       Just _  -> firstPtr
                       Nothing -> Just pos
               walk off off cap buf cursor firstPtr'
           | otherwise -> throwE "unsupported label type"

-- Grow @buf@ when @cursor + need@ would overflow @cap@.  Growth is
-- @max needed (cap + cap \`shiftR\` 1)@ (1.5x), capped at 'maxWireLen'
-- so we never allocate beyond the wire-form limit.  Returns the
-- (possibly resized) buffer and its new capacity.
ensureCap :: MutableByteArray s -> Int -> Int -> Int
          -> ST s (MutableByteArray s, Int)
ensureCap buf cap cursor need
    | needed <= cap = pure (buf, cap)
    | otherwise     = do
        let !grown  = cap + cap `shiftR` 1
            !newCap = min maxWireLen (max needed grown)
        buf' <- A.resizeMutableByteArray buf newCap
        pure (buf', newCap)
  where
    !needed = cursor + need
