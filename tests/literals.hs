{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module Main (main) where

import qualified Data.ByteString.Short as SB
import qualified System.Exit as Sys

import Net.DNSBase.Domain

import LiteralsParser (testParser, mkWire)

----------------------------------------------------------------------
-- Splice values (built at compile time; the @testParser@ runs in
-- the Q monad during these splices, and a build failure here would
-- mean the dnLit / mbLit machinery rejects valid input).
----------------------------------------------------------------------

dnExample :: Domain
dnExample = $$(dnLit testParser "example.org")

mbAt :: Domain
mbAt = $$(mbLit testParser "user@example.org")

mbDot :: Domain
mbDot = $$(mbLit testParser "user.example.org")

mbBare :: Domain
mbBare = $$(mbLit testParser "postmaster")

----------------------------------------------------------------------
-- Test plumbing (plain stdio, matches tests/domain.hs style).
----------------------------------------------------------------------

fatal :: String -> IO ()
fatal msg = do
    putStrLn $ "literals: " ++ msg
    Sys.exitWith (Sys.ExitFailure 1)

eqOrDie :: (Eq a, Show a) => String -> a -> a -> IO ()
eqOrDie name expected actual
    | expected == actual = pure ()
    | otherwise = fatal $ name ++ ": expected " ++ show expected
                               ++ ", got " ++ show actual

leftOrDie :: Show a => String -> Either e a -> IO ()
leftOrDie name r = case r of
    Left _  -> pure ()
    Right x -> fatal $ name ++ ": expected Left, got Right " ++ show x

----------------------------------------------------------------------
-- Tests
----------------------------------------------------------------------

main :: IO ()
main = do
    -- dnLit / mbLit smoke tests.
    eqOrDie "dnLit/example.org"
            (mkWire ["example", "org"])
            (shortBytes dnExample)
    eqOrDie "mbLit/@"
            (mkWire ["user", "example", "org"])
            (shortBytes mbAt)
    eqOrDie "mbLit/."
            (mkWire ["user", "example", "org"])
            (shortBytes mbDot)
    eqOrDie "mbLit/bare"
            (mkWire ["postmaster"])
            (shortBytes mbBare)

    -- parseMbox positive cases.
    eqOrDie "parseMbox/@"
            (Right (mkWire ["user", "example", "org"]))
            (shortBytes <$> parseMbox testParser "user@example.org")
    eqOrDie "parseMbox/."
            (Right (mkWire ["user", "example", "org"]))
            (shortBytes <$> parseMbox testParser "user.example.org")
    eqOrDie "parseMbox/bare"
            (Right (mkWire ["postmaster"]))
            (shortBytes <$> parseMbox testParser "postmaster")
    eqOrDie "parseMbox/bare-trailing-dot"
            (Right (mkWire ["postmaster"]))
            (shortBytes <$> parseMbox testParser "postmaster.")
    eqOrDie "parseMbox/bare-trailing-at"
            (Right (mkWire ["postmaster"]))
            (shortBytes <$> parseMbox testParser "postmaster@")
    eqOrDie "parseMbox/DDD-escape"
            (Right (mkWire ["A.B", "org"]))
            (shortBytes <$> parseMbox testParser "A\\046B.org")
    eqOrDie "parseMbox/C-escape-dot"
            (Right (mkWire ["a.b", "org"]))
            (shortBytes <$> parseMbox testParser "a\\.b.org")
    eqOrDie "parseMbox/C-escape-at"
            (Right (mkWire ["a@b", "org"]))
            (shortBytes <$> parseMbox testParser "a\\@b.org")
    eqOrDie "parseMbox/escaped-@-then-real-@"
            (Right (mkWire ["u@v", "example", "org"]))
            (shortBytes <$> parseMbox testParser "u\\@v@example.org")
    -- EAI: literal non-ASCII Chars are UTF-8 encoded into the
    -- localpart wire bytes.  "виктор" -> UTF-8 0xD0 B2 D0 B8 D0
    -- BA D1 82 D0 BE D1 80 (12 bytes).  The IsString instance for
    -- ShortByteString does a byte-per-Char Latin-1 truncation, so
    -- the expected-bytes literal below is the literal wire form.
    eqOrDie "parseMbox/utf8-cyrillic-localpart"
            (Right (mkWire [ "\xD0\xB2\xD0\xB8\xD0\xBA\xD1\x82\xD0\xBE\xD1\x80"
                           , "example", "org" ]))
            (shortBytes <$> parseMbox testParser "\1074\1080\1082\1090\1086\1088@example.org")

    -- parseMbox negative cases.
    leftOrDie "parseMbox/empty-localpart"
              (parseMbox testParser "@example.org")
    leftOrDie "parseMbox/bad-escape-truncated"
              (parseMbox testParser "u\\")
    -- EAI: \DDD with DDD >= 128 is rejected (no raw high octets
    -- in a pure-ASCII-or-UTF-8 localpart).
    leftOrDie "parseMbox/high-DDD-escape"
              (parseMbox testParser "u\\200v@example.org")
    -- EAI: \C with non-ASCII C is rejected for the same reason.
    leftOrDie "parseMbox/high-C-escape"
              (parseMbox testParser "u\\\233v@example.org")
    leftOrDie "parseMbox/unknown-domain"
              (parseMbox testParser "user@bogus\\")  -- malformed escape rejects in Parse8

    -- wireToDomain positive cases.
    eqOrDie "wireToDomain/root"
            (Just (SB.singleton 0))
            (shortBytes <$> wireToDomain (SB.singleton 0))
    eqOrDie "wireToDomain/single"
            (Just (mkWire ["org"]))
            (shortBytes <$> wireToDomain (mkWire ["org"]))
    eqOrDie "wireToDomain/multi"
            (Just (mkWire ["example", "org"]))
            (shortBytes <$> wireToDomain (mkWire ["example", "org"]))

    -- wireToDomain negative cases (raw byte sequences via SB.pack
    -- so the inputs are unambiguous regardless of OverloadedStrings
    -- decoding).
    eqOrDie "wireToDomain/empty"
            Nothing
            (shortBytes <$> wireToDomain SB.empty)
    eqOrDie "wireToDomain/no-terminator"
            Nothing
            (shortBytes <$> wireToDomain (SB.pack [3, 0x6f, 0x72, 0x67]))
    eqOrDie "wireToDomain/extra-bytes-after-root"
            Nothing
            (shortBytes <$> wireToDomain (SB.pack [3, 0x6f, 0x72, 0x67, 0, 0]))
    eqOrDie "wireToDomain/lying-label-length"
            Nothing
            (shortBytes <$> wireToDomain (SB.pack [16, 0x6f, 0x6f, 0x70, 0x73, 0]))

    putStrLn "literals: all tests passed"
