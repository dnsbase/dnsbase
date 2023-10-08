module Net.DNSBase.Internal.NameComp
    ( NCTree
    , empty
    , insert
    , lookup
    ) where

import Prelude hiding (lookup)
import Control.Monad.ST as ST
import qualified Data.ByteString as B
import qualified Data.HashTable.ST.Basic as LH
import qualified Data.HashTable.Class as H

type Path = [B.ByteString]
type Map s = LH.HashTable s B.ByteString
data NCTree s = NCTree (Map s (NCTree s)) Int

-- | Create a root node with given value
empty :: Int -> ST.ST s (NCTree s)
empty n = flip NCTree n <$> H.new

-- | Insert a domain with the given labels with last label ending at given
-- offset (if stored uncompressed).  The caller MUST not insert any paths whose
-- tail lies beyond the first 16k of the DNS message.  That is the end offset
-- must not exceed @0x3fff@.
insert :: Path -> Int -> NCTree s -> ST.ST s ()
insert = go
  where
    go :: Path -> Int  -> NCTree s -> ST.ST s ()
    go (!l:ls) !end !(NCTree m _) =
        H.mutateST m l $ alter ls $! end - B.length l - 1
    go _ _ _ = pure ()

    -- | Alter (create or update) the node with given index and start position
    alter :: Path -> Int -> Maybe (NCTree s) -> ST.ST s (Maybe (NCTree s), ())
    alter !ls !start !old = case old of
        -- At existing intermediate nodes recurse to store the rest of the path
        Just  n | null ls   -> pure $ node n
                | otherwise -> node n <$ go ls start n
        -- In new intermediate nodes store the tip offset + distance from tip
        Nothing | null ls   -> node <$> empty start
                | otherwise -> do
                    e <- empty start
                    node e <$ go ls start e
      where
        node n = (Just n, ())

-- | Return the length of the path prefix (domain suffix) and corresponding
-- offset for the input path (reversed list of wire-form labels), counting both
-- the length (1) and payload size of each label, not including the terminal
-- NUL label.
lookup :: Path -> (NCTree s) -> ST.ST s (Int, Int)
lookup labels root = go labels root 0
  where
    go (!l:ls) !(NCTree m off) !slen = do
        mn <- H.lookup m l
        case mn of
            Just n  -> go ls n $! slen + B.length l + 1
            _       -> pure (slen, off)
    go _ (NCTree _ off) slen = pure (slen, off)
