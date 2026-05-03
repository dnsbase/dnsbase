{-# LANGUAGE
    OverloadedStrings
  , TemplateHaskell
  #-}
module Main (main) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Short as SB
import qualified System.Exit as Sys

import Net.DNSBase.Domain

check :: (B.ByteString -> Either Domain8Err Domain)
      -> SB.ShortByteString
      -> Int
      -> Maybe [SB.ShortByteString]
      -> IO ()
check f bs len labels = do
    case f (SB.fromShort bs) of
        Left _   | Nothing <- labels    -> pure ()
        Right dn | Just (toLabels dn) == labels
                 , SB.length (shortBytes dn) == len+1  -> pure ()
        result  -> do
                   putStrLn $ "Failed: " ++ show bs
                   putStrLn $ "Parsed: " ++ show result
                   putStrLn $ "Labels: " ++ show (toLabels <$> result)
                   putStrLn $ "Wirelen: " ++ show (SB.length . shortBytes <$> result)
                   Sys.exitWith $ Sys.ExitFailure 1

main :: IO ()
main = do
    check makeDomain8 "" 0 $ Just []
    check makeDomain8 "." 0 $ Just []
    check makeDomain8 ".." 0 Nothing

    check makeDomain8 "\\." 2 $ Just ["."]
    check makeDomain8 "\\.." 2 $ Just ["."]
    check makeDomain8 "\\.com" 5 $ Just [".com"]
    check makeDomain8 "\\\\" 2 $ Just ["\\"]
    check makeDomain8 "\\\\." 2 $ Just ["\\"]
    check makeDomain8 "\\x" 2 $ Just ["x"]
    check makeDomain8 "x\\y" 3  $ Just ["xy"]
    check makeDomain8 "x\\y." 3  $ Just ["xy"]
    check makeDomain8 "x.\\" 0 Nothing
    check makeDomain8 "x.com\\" 0 Nothing

    check makeDomain8 ".com" 0 Nothing
    check makeDomain8 "com" 4 $ Just ["com"]
    check makeDomain8 "com." 4 $ Just ["com"]
    check makeDomain8 "example.com" 12 $ Just ["example", "com"]
    check makeDomain8 "example.com." 12 $ Just ["example", "com"]
    check makeDomain8 "exa\\mple.com" 12 $ Just ["example", "com"]
    check makeDomain8 "ex\\097mple.com" 12 $ Just ["example", "com"]
    check makeDomain8 "a..b" 0 $ Nothing

    let a i = SB.replicate i 97
    let dot = SB.singleton 0x2e
    check makeDomain8 (a 63) 64 $ Just [a 63]
    check makeDomain8 ((a 63) <> dot <> (a 63) <> dot <> (a 63) <> dot <> (a 61))
                      254 $ Just [a 63, a 63, a 63, a 61]
    check makeDomain8 ((a 63) <> dot <> (a 63) <> dot <> (a 63) <> dot <> (a 61) <> dot)
                      254 $ Just [a 63, a 63, a 63, a 61]

    let b i = mconcat $ replicate i $ SB.pack [98, 0x2e]
    check makeDomain8 (b 1) 2 $ Just ["b"]
    check makeDomain8 (b 127) 254 $ Just $ replicate 127 "b"
    check makeDomain8 (b 127 <> dot) 0 $ Nothing
    check makeDomain8 (b 128) 0 Nothing

    check makeMbox8 "" 0 $ Just []
    check makeMbox8 "." 0 $ Just []
    check makeMbox8 ".." 0 Nothing
    check makeMbox8 "@." 0 Nothing
    check makeMbox8 "@" 0 $ Just []
    check makeMbox8 "@@" 0 Nothing
    check makeMbox8 ".@" 2 $ Just ["."]
    check makeMbox8 ".@" 2 $ Just ["."]
    check makeMbox8 "a.b@" 4 $ Just ["a.b"]
    check makeMbox8 "a.b@." 4 $ Just ["a.b"]
    check makeMbox8 "example.com" 12 $ Just ["example","com"]
    check makeMbox8 "first.last@example.com" 23 $ Just ["first.last","example","com"]
    check makeMbox8 "first\\.last.example.com" 23 $ Just ["first.last","example","com"]

    check makeMbox8 (b 127) 254 $ Just $ replicate 127 "b"
    check makeMbox8 ("b@" <> b 125 <> SB.singleton 98) 254 $ Just $ replicate 127 "b"
    check makeMbox8 ("b@" <> b 126) 254 $ Just $ replicate 127 "b"
    check makeMbox8 (b 126 <> SB.pack [98, 64]) 0 Nothing
    check makeMbox8 (b 128) 0 Nothing

    check makeMbox8 (a 63) 64 $ Just [a 63]
    check makeMbox8 ((a 63) <> dot <> (a 63) <> dot <> (a 63) <> dot <> (a 61))
                    254 $ Just [a 63, a 63, a 63, a 61]
    check makeMbox8 ((a 63) <> dot <> (a 63) <> dot <> (a 63) <> dot <> (a 61) <> dot)
                    254 $ Just [a 63, a 63, a 63, a 61]
