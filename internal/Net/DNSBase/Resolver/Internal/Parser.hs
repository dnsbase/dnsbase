module Net.DNSBase.Resolver.Internal.Parser
    ( getDefaultNameservers
    ) where

import Control.Monad.Trans (lift)
import Data.Char (isSpace)
import Data.List (dropWhileEnd, stripPrefix, uncons)
import Data.Maybe (catMaybes)
import System.IO.Error (catchIOError)

import Net.DNSBase.Resolver.Internal.Types

-- XXX: this implementation is a WIP for completeness and should be improved ASAP
getDefaultNameservers :: FilePath -> DNSIO [NameserverSpec]
getDefaultNameservers fp = lift $ parseFile `catchIOError` (const $ return [])
  where
    parseFile :: IO [NameserverSpec]
    parseFile = catMaybes . map parseLine . lines <$> readFile fp

    parseLine :: String -> Maybe NameserverSpec
    parseLine (stripPrefix "nameserver" -> Just rest)
        | Just (h, t) <- uncons rest
        , isSpace h
        , name <- dropWhileEnd isSpace $ dropWhile isSpace t
        , not $ null name
        = Just $ NameserverSpec name Nothing
    parseLine _ = Nothing
        
