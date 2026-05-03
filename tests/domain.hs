{-# LANGUAGE
    OverloadedStrings
  , TemplateHaskell
  #-}
module Main (main) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Short as SB
import qualified System.Exit as Sys

import Net.DNSBase.Domain

check :: (B.ByteString -> Maybe Domain)
      -> SB.ShortByteString
      -> Int
      -> Maybe [SB.ShortByteString]
      -> IO ()
check f bs len labels = do
    case f (SB.fromShort bs) of
        Nothing | Nothing <- labels     -> pure ()
        Just dn | Just (toLabels dn) == labels
                , SB.length (shortBytes dn) == len+1  -> pure ()
        result  -> do
                   putStrLn $ "Failed: " ++ show bs
                   putStrLn $ "Parsed: " ++ show result
                   putStrLn $ "Labels: " ++ show (toLabels <$> result)
                   putStrLn $ "Wirelen: " ++ show (SB.length . shortBytes <$> result)
                   Sys.exitWith $ Sys.ExitFailure 1

main :: IO ()
main = do
    check parseDomain8 "" 0 $ Just []
    check parseDomain8 "." 0 $ Just []
    check parseDomain8 ".." 0 Nothing

    check parseDomain8 "\\." 2 $ Just ["."]
    check parseDomain8 "\\.." 2 $ Just ["."]
    check parseDomain8 "\\.com" 5 $ Just [".com"]
    check parseDomain8 "\\\\" 2 $ Just ["\\"]
    check parseDomain8 "\\\\." 2 $ Just ["\\"]
    check parseDomain8 "\\x" 2 $ Just ["x"]
    check parseDomain8 "x\\y" 3  $ Just ["xy"]
    check parseDomain8 "x\\y." 3  $ Just ["xy"]
    check parseDomain8 "x.\\" 0 Nothing
    check parseDomain8 "x.com\\" 0 Nothing

    check parseDomain8 ".com" 0 Nothing
    check parseDomain8 "com" 4 $ Just ["com"]
    check parseDomain8 "com." 4 $ Just ["com"]
    check parseDomain8 "example.com" 12 $ Just ["example", "com"]
    check parseDomain8 "example.com." 12 $ Just ["example", "com"]
    check parseDomain8 "exa\\mple.com" 12 $ Just ["example", "com"]
    check parseDomain8 "ex\\097mple.com" 12 $ Just ["example", "com"]
    check parseDomain8 "a..b" 0 $ Nothing

    let a i = SB.replicate i 97
    let dot = SB.singleton 0x2e
    check parseDomain8 (a 63) 64 $ Just [a 63]
    check parseDomain8 ((a 63) <> dot <> (a 63) <> dot <> (a 63) <> dot <> (a 61))
                      254 $ Just [a 63, a 63, a 63, a 61]
    check parseDomain8 ((a 63) <> dot <> (a 63) <> dot <> (a 63) <> dot <> (a 61) <> dot)
                      254 $ Just [a 63, a 63, a 63, a 61]

    let b i = mconcat $ replicate i $ SB.pack [98, 0x2e]
    check parseDomain8 (b 1) 2 $ Just ["b"]
    check parseDomain8 (b 127) 254 $ Just $ replicate 127 "b"
    check parseDomain8 (b 127 <> dot) 0 $ Nothing
    check parseDomain8 (b 128) 0 Nothing

    check parseMbox8 "" 0 $ Just []
    check parseMbox8 "." 0 $ Just []
    check parseMbox8 ".." 0 Nothing
    check parseMbox8 "@." 0 Nothing
    check parseMbox8 "@" 0 $ Just []
    check parseMbox8 "@@" 0 Nothing
    check parseMbox8 ".@" 2 $ Just ["."]
    check parseMbox8 ".@" 2 $ Just ["."]
    check parseMbox8 "a.b@" 4 $ Just ["a.b"]
    check parseMbox8 "a.b@." 4 $ Just ["a.b"]
    check parseMbox8 "example.com" 12 $ Just ["example","com"]
    check parseMbox8 "first.last@example.com" 23 $ Just ["first.last","example","com"]
    check parseMbox8 "first\\.last.example.com" 23 $ Just ["first.last","example","com"]

    check parseMbox8 (b 127) 254 $ Just $ replicate 127 "b"
    check parseMbox8 ("b@" <> b 125 <> SB.singleton 98) 254 $ Just $ replicate 127 "b"
    check parseMbox8 ("b@" <> b 126) 254 $ Just $ replicate 127 "b"
    check parseMbox8 (b 126 <> SB.pack [98, 64]) 0 Nothing
    check parseMbox8 (b 128) 0 Nothing

    check parseMbox8 (a 63) 64 $ Just [a 63]
    check parseMbox8 ((a 63) <> dot <> (a 63) <> dot <> (a 63) <> dot <> (a 61))
                   254 $ Just [a 63, a 63, a 63, a 61]
    check parseMbox8 ((a 63) <> dot <> (a 63) <> dot <> (a 63) <> dot <> (a 61) <> dot)
                      254 $ Just [a 63, a 63, a 63, a 61]
