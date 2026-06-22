-- |
-- Module      : Net.DNSBase.Internal.NameComp
-- Description : DNS name-compression state for the wire-format encoder
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
--
-- A mutable trie whose keys ('NCNode') pair a parent suffix's
-- message offset with a chunk slice of the owning name's wire form,
-- mapping each entry to the offset at which the corresponding suffix
-- first appears in the output message.  Used by
-- 'Net.DNSBase.Encode.Internal.State.putDomain' to emit DNS name
-- pointers per RFC 1035 §4.1.4.
--
-- A /chunk/ is a contiguous run of consecutive DNS labels (with their
-- length bytes) covering at least 'minChunkBytes' bytes of wire form.
-- Chunks are anchored at the tail of the name: starting from the
-- rightmost label, each chunk extends leftward until it reaches the
-- minimum-size threshold, at which point a new chunk begins.  The
-- leftmost chunk may be smaller than the threshold (it inherits
-- whatever labels are left over).  A label too short to make a
-- worthwhile pointer target on its own is therefore grouped with its
-- right neighbours.
--
-- The trie itself is a single flat hashtable; each name with @C@
-- chunks contributes @C@ entries, and each traversal step is one
-- hashtable lookup matching whole chunks.
--
-- The chunk component of each key is a slice (offset + length) into
-- a 'ShortByteString' belonging to the 'Domain' that first introduced
-- the chunk.  The slice retains a reference to that buffer for the
-- duration of the encode, so chunk bytes are not copied into freshly
-- allocated keys.
-- {-# LANGUAGE BangPatterns    #-}
{-# LANGUAGE MagicHash       #-}
-- {-# LANGUAGE PatternSynonyms #-}
module Net.DNSBase.Internal.NameComp
    ( NCMap
    , empty
    , lookupAndRegister
    ) where

import Net.DNSBase.Internal.Util

import qualified Data.ByteString.Short as SB
import qualified Data.HashTable.Class as H
import qualified Data.HashTable.ST.Basic as LH
import Control.Monad.ST (ST)
import Data.Foldable (foldlM)
import Data.Hashable (Hashable(..), hashByteArrayWithSalt)
import Data.Primitive.ByteArray
    ( ByteArray#
    , MutableByteArray
    , compareByteArrays
    , newByteArray
    , readByteArray
    , writeByteArray
    )

--------------------------------------------------------------------------------
-- Compression-trie node
--------------------------------------------------------------------------------

-- A compression-trie node identified by its parent suffix's
-- message-offset and a slice into the owning name's 'ShortByteString'
-- holding the chunk's wire bytes.  The byte array reference keeps
-- the source buffer alive as long as the node is reachable from the
-- map; 'Eq' and 'Hashable' read the byte range in place.
--
-- Field widths reflect the bounds: parent offsets are clamped at the
-- 14-bit pointer range (with @0xFFFF@ as the @ROOT@ sentinel,
-- distinct from any real offset because real offsets never exceed
-- @0x3FFF@), and a DNS name is at most 255 wire bytes so the chunk
-- offset and length both fit in a byte.
data NCNode = NCNode
                   !ByteArray#                  -- owning byte array
    {-# UNPACK #-} !Word16                      -- parent offset
    {-# UNPACK #-} !Word8                       -- chunk byte offset
    {-# UNPACK #-} !Word8                       -- chunk byte length

instance Eq NCNode where
    NCNode aA pA offA lenA == NCNode aB pB offB lenB
      | pA /= pB || lenA /= lenB = False
      | otherwise =
          compareByteArrays (ByteArray aA) (fromIntegral offA)
                            (ByteArray aB) (fromIntegral offB)
                            (fromIntegral lenA) == EQ

instance Hashable NCNode where
    hashWithSalt salt (NCNode ba parent off len) =
        hashByteArrayWithSalt ba (fromIntegral off) (fromIntegral len)
            (salt `hashWithSalt` (fromIntegral parent :: Int))

--------------------------------------------------------------------------------
-- Public API
--------------------------------------------------------------------------------

-- | The compression state: a single mutable hashtable keyed on
-- 'NCNode' (parent offset plus chunk slice), mapping each entry to
-- the message offset at which the suffix @chunk.parent-suffix@
-- first appears.
newtype NCMap s = NCMap (LH.HashTable s NCNode Int)

-- | Create a fresh empty compression state.
empty :: ST s (NCMap s)
empty = NCMap <$> H.new

-- The 14-bit pointer cap.  Children with absolute offsets exceeding
-- this can't be the target of an RFC 1035 compression pointer, so
-- registering them is pointless.
maxPtr :: Int
maxPtr = 0x3fff

-- Sentinel parent-offset for the root level of the trie.  Distinct
-- from any real wire-message offset, which is non-negative.
parentRoot :: Int
parentRoot = -1

-- The pointer high-bits mask: a name pointer is @0xC000 .|. target@.
pointerMark :: Int
pointerMark = 0xC000

-- Minimum byte count for a chunk.  A trie entry pointing at @n@ wire
-- bytes pays back @n - 2@ bytes on a hit, so chunks shorter than
-- about 4 bytes barely earn their keep; 8 puts every registered
-- chunk solidly into "worth pointing at" territory while still
-- exploiting the long zone-suffix sharing that dominates real DNS
-- traffic.
minChunkBytes :: Word8
minChunkBytes = 8

-- Max chunks per name.  Each chunk has at least 'minChunkBytes' wire
-- bytes except possibly the leftmost leftover, so at most
-- @floor(255 \/ minChunkBytes) + 1@.
maxChunks :: Int
maxChunks = fromIntegral $ 1 + 255 `quot` minChunkBytes

-- | Look up and register a domain in one walk.
--
-- Given the wire form @dname@ of a domain (including its terminal NUL
-- byte) about to be emitted at message offset @baseOff@, walk its
-- chunks root-first.  In the prefix that already matches the map,
-- thread parent offsets through hits; at the first miss (or running
-- off the end), register the new entries the input contributes.
-- Registrations whose absolute offsets exceed the 14-bit pointer
-- range ('maxPtr') are silently dropped: the input can still benefit
-- from compression against existing entries, but won't itself be the
-- target of future pointers.
--
-- Returns 'Nothing' when the name has no compressible suffix in the
-- map (so the caller emits the full wire form), or
-- @'Just' (headBytes, ptr)@ to indicate the caller should emit the
-- first @headBytes@ bytes of the wire form verbatim, then the 2-byte
-- pointer word @ptr@.
lookupAndRegister :: forall s. ShortByteString
                  -> Int
                  -> NCMap s
                  -> ST s (Maybe (Int, Word16))
lookupAndRegister !dname@(SBS nameArr) !baseOff (NCMap m) = do
    if | wlen == 1 -> pure Nothing -- root domain
       | otherwise -> do
            chunkArr <- newByteArray maxChunks
            nChunks  <- buildChunks chunkArr
            phase1 chunkArr nChunks 0 (wlen - 1) parentRoot Nothing
  where
    !wlen = SB.length dname

    -- Compute offsets of one-or-more chunks of consecutive labels,
    -- each at least 'minChunkBytes' wire bytes (the leftmost
    -- leftover may be smaller).  Chunks are emitted in root-first
    -- iteration order: @chunkArr[0]@ is the outermost (rightmost)
    -- chunk, @chunkArr[nChunks - 1]@ is the innermost (leftmost).
    --
    buildChunks :: MutableByteArray s -> ST s Int
    buildChunks carr = walk 0 []
      where
        walk :: Word8 -> [Word8] -> ST s Int
        walk !pos@((+ 1) . SB.index dname . fromIntegral -> !llen) !lens
            | llen /= 1 = walk (pos + llen) (llen : lens)
            | otherwise = foldlM step (0, 1, fromIntegral $ wlen - 1) lens >>= \ case
                (!ix, 0, _) -> pure ix
                (!ix, _, _) -> (ix + 1) <$ writeByteArray @Word8 carr ix 0

        step :: (Int, Word8, Word8) -> Word8 -> ST s (Int, Word8, Word8)
        step (!ix, !acc, !end) !llen
            | acc' < minChunkBytes = pure (ix, acc', start)
            | otherwise = (ix + 1, 0, start) <$ writeByteArray carr ix start
          where
            !acc'  = acc + llen
            !start = end - llen

    -- Lookup phase.  Walks chunks root-first; each step either
    -- advances the parent offset on a hit, or transitions to phase 2
    -- on the first miss.  @chunkEnd@ is the exclusive end position
    -- of the current chunk in the wire form (one past its last
    -- byte); each step's @chunkEnd@ becomes the next step's via the
    -- current chunk's start (chunks are contiguous in the wire form,
    -- with the next-outer chunk lying immediately to the right).
    -- The 'acc' carries @(target, matchedChunkStart)@ for the
    -- deepest match seen so far, or 'Nothing' if no chunk has
    -- matched yet.
    phase1
        :: MutableByteArray s
        -> Int                                          -- chunk count
        -> Int                                          -- current chunk index
        -> Int                                          -- chunk end (exclusive)
        -> Int                                          -- current parent_off
        -> Maybe (Int, Int)                             -- (target, matchedChunkStart)
        -> ST s (Maybe (Int, Word16))
    phase1 carr nChunks i chunkEnd parent acc
      | i >= nChunks = pure (finalize acc)
      | otherwise = do
          cs <- readByteArray carr i :: ST s Word8
          let !chunkStart = fromIntegral cs :: Int
              !chunkLen   = chunkEnd - chunkStart
              !node       = NCNode nameArr (fromIntegral parent)
                                   cs (fromIntegral chunkLen)
          mhit <- H.lookup m node
          case mhit of
              Just hitOff ->
                  phase1 carr nChunks (i + 1) chunkStart hitOff
                         (Just (hitOff, chunkStart))
              Nothing     -> phase2 carr nChunks i chunkEnd parent acc

    -- Insert phase.  Walks the remainder of chunks from index @i@
    -- onward, registering each at its absolute offset.  Drops
    -- out-of-range registrations silently.  Returns whatever
    -- compression decision was frozen at the transition.
    phase2
        :: MutableByteArray s
        -> Int
        -> Int
        -> Int
        -> Int
        -> Maybe (Int, Int)
        -> ST s (Maybe (Int, Word16))
    phase2 carr nChunks i chunkEnd parent acc
      | i >= nChunks = pure (finalize acc)
      | otherwise = do
          cs <- readByteArray carr i :: ST s Word8
          let !chunkStart = fromIntegral cs :: Int
              !chunkLen   = chunkEnd - chunkStart
              !node       = NCNode nameArr (fromIntegral parent)
                                   cs (fromIntegral chunkLen)
              !newOff     = baseOff + chunkStart
          when (newOff <= maxPtr) $
              H.insert m node newOff
          phase2 carr nChunks (i + 1) chunkStart newOff acc

    finalize :: Maybe (Int, Int) -> Maybe (Int, Word16)
    finalize Nothing           = Nothing
    finalize (Just (tgt, cs))  = Just (cs, mkPtr tgt)

    mkPtr :: Int -> Word16
    mkPtr off = fromIntegral (pointerMark .|. off)
