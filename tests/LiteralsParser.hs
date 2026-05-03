-- |
-- Module      : LiteralsParser
-- Description : Tiny test parser used by the literal-splice tests
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
--
-- Wraps the octet-level 'makeDomain8Str' parser for the dnLit \/
-- mbLit \/ parseMbox tests.  Defined in its own module so the TH
-- splices in @tests\/literals.hs@ can refer to it (Template-Haskell
-- staging forbids splices from referencing same-module top-level
-- bindings).
module LiteralsParser
    ( testParser
    , mkWire
    ) where

import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as SB
import Data.Text (Text)
import qualified Data.Text as T

import Net.DNSBase.Domain (Domain8Err, makeDomain8Str, shortBytes)

-- | Domain-name parser used by the dnLit \/ mbLit \/
-- decodePresentationMbox tests.  Wraps the byte-level
-- 'makeDomain8Str' to expose the @'Text' -> 'Either' e
-- 'ShortByteString'@ shape that 'dnLit' \/ 'mbLit' \/
-- 'decodePresentationMbox' expect.  No IDN machinery is involved;
-- this is the simplest real parser the test suite can hand to the
-- TH splices.
testParser :: Text -> Either Domain8Err ShortByteString
testParser = fmap shortBytes . makeDomain8Str . T.unpack

-- | Build a wire-form 'ShortByteString' from a list of unescaped
-- label bytes: each label is prefixed with its length byte and a
-- trailing root NUL closes the name.  Used by the tests to
-- describe expected outputs in label-list form.
mkWire :: [ShortByteString] -> ShortByteString
mkWire = foldr cat (SB.singleton 0)
  where
    cat l acc = SB.singleton (fromIntegral (SB.length l)) <> l <> acc
