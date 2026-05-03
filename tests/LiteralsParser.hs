-- |
-- Module      : LiteralsParser
-- Description : Tiny test parser used by the literal-splice tests
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
--
-- Adapter that turns the octet-level 'strToDomain8' parser into the
-- @(String -> Either e ShortByteString)@ shape the new 'dnLit' /
-- 'mbLit' / 'parseMbox' machinery expects.  Defined in its own
-- module so the TH splices in @tests\/literals.hs@ can refer to it
-- (Template-Haskell staging forbids splices from referencing
-- same-module top-level bindings).
module LiteralsParser
    ( testParser
    , mkWire
    ) where

import Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Short as SB

import Net.DNSBase.Domain (shortBytes)
import Net.DNSBase.Internal.Domain.Parse8 (strToDomain8)

-- | Domain-name parser used by the dnLit \/ mbLit \/ parseMbox
-- tests.  Delegates to the octet-level 'strToDomain8' and projects
-- to the wire-form bytes.  No IDN machinery is involved; this is
-- the simplest real parser the test suite can hand to the new
-- TH splices.
testParser :: String -> Either String ShortByteString
testParser s = case strToDomain8 s of
    Just d  -> Right (shortBytes d)
    Nothing -> Left s

-- | Build a wire-form 'ShortByteString' from a list of unescaped
-- label bytes: each label is prefixed with its length byte and a
-- trailing root NUL closes the name.  Used by the tests to
-- describe expected outputs in label-list form.
mkWire :: [ShortByteString] -> ShortByteString
mkWire = foldr cat (SB.singleton 0)
  where
    cat l acc = SB.singleton (fromIntegral (SB.length l)) <> l <> acc
