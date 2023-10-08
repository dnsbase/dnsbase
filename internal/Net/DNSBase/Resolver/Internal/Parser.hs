module Net.DNSBase.Resolver.Internal.Parser
    ( getDefaultDnsServers
    ) where

import Control.Monad.Trans (lift)
import Data.Char (isSpace)
import Data.List (dropWhileEnd, stripPrefix)
import Data.Maybe (catMaybes)
import Network.Socket (HostName)
import System.IO.Error (catchIOError)

import Net.DNSBase.Resolver.Internal.Types

-- XXX: this implementation is a WIP for completeness and should be improved ASAP
getDefaultDnsServers :: FilePath -> DNSIO [HostName]
getDefaultDnsServers fp = lift $ parseFile `catchIOError` (const $ return [])
  where
    parseFile :: IO [HostName]
    parseFile = do
        contents <- readFile fp
        let ls = catMaybes . map (stripPrefix "nameserver") . lines $ contents
        return $ map trim ls

    trim :: String -> String
    trim = dropWhile isSpace . dropWhileEnd isSpace
