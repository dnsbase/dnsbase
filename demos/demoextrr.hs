{- |
Module      : Main
Description : RData extension demo
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : experimental

A proof of concept demo that shows how to extend or customise the
@dnsbase@ stub resolver library with support for a custom RR type,
is either not yet implemented by library, or perhaps the
application prefers a different representation of the decoded
data.

User-registered extensions take precedence over any built-in type
at the same codepoint, ensuring stable applicatoin behaviour even
if the library later implements a type initially defined as an
extension by the application.

To drive home that point, here we reimplement the stand IPv4
address RR type @A@, to store it directly as a 'Word32' value,
rather than the @Data.IP@ newtype representation as an 'IPv4'
object, and override the presentation form to just output the
hexadecimal bytes, with a new made up @HEXA@ name for the record
type.
-}

{-# LANGUAGE
    BlockArguments
  , LambdaCase
  , PatternSynonyms
  , RequiredTypeArguments
  , TypeApplications
  #-}
module Main (main) where
import Data.ByteString.Builder as B
import Data.Word (Word32)
import System.Environment (getArgs, getProgName)
import System.Exit (exitFailure)
import System.IO (stderr, hPutStrLn)

-- | The "kitchen-sink" import of most of the library.
-- More selective imports of specific submodules are
-- available and of course a qualified import may be
-- a sensible option.
--
import Net.DNSBase

-- | Our alternative/preferred pattern synonym for the
-- "A" RRTYPE, it won't clash withe the library.
--
pattern EXT_HEXA :: RRTYPE
pattern EXT_HEXA = RRTYPE 1 -- Same as "A"

-- Represented as a 'Data.Word.Word32' value
--
data T_ext_hexa = T_EXT_HEXA Word32
    deriving (Eq, Ord, Show)

-- | Presented as 8 hex nibbles
-- The presentation builders in @dnsbase@ all take a
-- continuation argument, so that a chain of builders
-- becomes b1 <> (b2 <> (b3 <> (... (bN k)...))).
--
instance Presentable T_ext_hexa where
    present (T_EXT_HEXA w) k =
        B.word32HexFixed w <> k

-- | The minimal required methods are generally
-- sufficient.  Here the only non-required addition
-- is "rdTypePres", which assumes that the codepoint
-- is not yet known to the library.
--
instance KnownRData T_ext_hexa where
    -- | Required codepoint
    rdType _ = A

    -- Optional presentation-form codepoint name, defaults to the
    -- name as known to the library, or else "TYPE<n>".
    --
    rdTypePres _ = present @String "HEXA"

    -- Fixed-width encoder
    rdEncode (T_EXT_HEXA w) = putSizedBuilder $! mbWord32 w

    -- The decoder hides the polymorphic payload inside the
    -- existential 'RData' wrapper.  The parser monad makes
    -- sure the lengths consumed exactly match the available input
    -- (get32 raises a @Left why@ with less thatn 8 bytes, the
    -- third /length/ argument can be entirely ignored when
    -- decoding known fixed-length inputs (the first two
    -- are also ignored in most cases).
    --
    rdDecode _ _ _ = RData . T_EXT_HEXA <$> get32

-- | Add our RR type extension to a resolver configuration
--
withHEXA :: ResolverConf -> ResolverConf
withHEXA = registerRRtype T_ext_hexa

-- | Complain and exit with an error
--
bail :: String -> IO ()
bail why = hPutStrLn stderr why >> exitFailure

-- | Complain and keep going, producing a blank-line
-- terminated comment in place of the expected RRs.
--
carp :: Show a => String -> String -> a -> IO ()
carp what which why =
    putStrLn $ what ++ " '" ++ which ++ "': " ++ (show why) ++ "\n"

-- | For each domain in the command-line argument list
-- look up its @HEXA@ (really "A") records, and print
-- the results.  If the lookup fails, report the error
-- as a DNS-style comment (leading @;@) -- and keep going.
--
main :: IO ()
main = getArgs >>= \ case
    [] -> do
        prog <- getProgName
        bail $ "Usage: " ++ prog ++ " domain [...]"

    -- Build seed from extended resolver config
    args -> do
        let conf = withHEXA defaultResolvConf
        makeResolvSeed conf >>= \ case
            Left why ->
                bail $ "Resolver configuration error: " ++ show why

            -- Instantiate the extended resolver once, and run one
            -- or more queries in sequence.  For parallel lookups
            -- separate per-thread resolvers need to be instantiated
            -- for each 'forkIO' /thread/ (typically from the same
            -- /seed/).
            --
            Right seed -> withResolver seed \ rslv -> runAll rslv args
  where
    runAll :: Resolver -> [String] -> IO ()
    runAll = mapM_ . runOne

    -- Retrieve an print the answer RRset, the 'lookupX'
    -- function can retrieve just an array of the desired
    -- record type, without the RR wrapping, but with the
    -- 'lookupAnswers' function we can also see the
    -- the record /owner/ names and custom "HEXA" typ
    -- name strings.
    --
    runOne rslv dom = case makeDomain8Str dom of
        Left why -> carp "; Error parsing" dom why
        Right dn -> do
            -- Issue the query with default controls.
            --
            lookupAnswers rslv mempty IN EXT_HEXA dn >>= \ case
                -- Handle SERVFAIL, timeouts, ...
                Left why -> carp "; Lookup error" dom why

                -- When no answers, output diagnostic comment.
                Right [] -> putBuilder $ present ';'
                    . presentSp dom . presentSp "HEXA"
                    . presentSp "NODATA" $ presentLn '\n' mempty

                -- Otherwise one answer RR per-line in presentation form
                -- followed by a blank line to terminate each complete
                -- answer RR set.
                Right rs -> putBuilder $ foldr presentLn nl rs
              where
                -- The terminator newline
                nl = present '\n' mempty
