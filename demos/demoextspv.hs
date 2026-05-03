{- |
Module      : Main
Description : SVCB / HTTPS service parameter extension demo
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : experimental

A proof of concept demo that shows how to extend or customise the
@dnsbase@ stub resolver library with support for an HTTPS / SVCB
service parameter ('SVCParamKey' / 'SVCParamValue' pair).

This kind of extension is in practice the most common one for
@dnsbase@ applications: new SvcParam keys are added to the IANA
SVCB registry on a regular basis, and an application that wants
to consume a key the library does not yet carry plugs it in via
'KnownSVCParamValue' rather than waiting for a library release.

User-registered extensions take precedence over any built-in
implementation at the same codepoint, ensuring stable application
behaviour even if the library later implements a key initially
defined as an extension by the application.

To drive home that override behaviour, this demo shadows the
standard @ipv4hint@ key (codepoint 4) with a representation that
stores each hint as a raw 'Data.Word.Word32' rather than the
library's 'Data.IP.IPv4' newtype, and presents each address as
eight hexadecimal nibbles under a made-up name @IPV4HEX@.

SVCB and HTTPS each carry their own copy of the SvcParam codec
map, so the registration is applied to both 'T_svcb' and
'T_https'.
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
-- @ipv4hint@ 'SVCParamKey' (codepoint 4).  In a qualified
-- import setup, @IPV4HINT@ from the library would also
-- work; the @EXT_@ prefix here is just a habit to keep
-- custom and built-in names visibly distinct.
--
pattern EXT_IPV4HEX :: SVCParamKey
pattern EXT_IPV4HEX = SVCParamKey 4 -- Same as "IPV4HINT"

-- | A non-empty list of IPv4 addresses, held as raw 32-bit
-- integers.  No @Data.IP@ involvement.
--
newtype SPV_ext_ipv4hex = SPV_EXT_IPV4HEX (NonEmpty Word32)
    deriving (Eq, Ord, Show)

-- | Present each address as eight hex nibbles, the first
-- separated from the key name by @=@ and any remaining
-- addresses by commas (the standard SvcParam presentation
-- shape).
--
-- The presentation builders in @dnsbase@ all take a
-- continuation argument, so that a chain of builders
-- becomes b1 <> (b2 <> (b3 <> (... (bN k)...))).
--
instance Presentable SPV_ext_ipv4hex where
    present (SPV_EXT_IPV4HEX (a :| as)) =
        present @String "IPV4HEX"
        . present '='
        . hex a
        . flip (foldr pnxt) as
      where
        hex w k = B.word32HexFixed w <> k
        pnxt w  = present ',' . hex w

-- | The minimal required methods are 'spvKey', 'encodeSPV',
-- and 'decodeSPV'.  Wire form is a sequence of 4-byte
-- big-endian IPv4 addresses; the SVCB framework owns the
-- surrounding @(key, length)@ frame, so 'encodeSPV' writes
-- only the payload bytes and the decoder consumes exactly
-- @len@ bytes.
--
instance KnownSVCParamValue SPV_ext_ipv4hex where
    -- | Required codepoint.
    --
    spvKey _ = EXT_IPV4HEX

    -- The encoder emits just the value bytes; the 2-byte
    -- length prefix that introduces every 'SVCParamValue'
    -- on the wire is handled by the SVCB-record framework.
    --
    encodeSPV (SPV_EXT_IPV4HEX hs) = mapM_ put32 hs

    -- The decoder hides the polymorphic payload inside the
    -- existential 'SVCParamValue' wrapper.  One mandatory
    -- address is read first (the value cannot be empty
    -- per RFC 9460), then 'getFixedWidthSequence' consumes
    -- a fixed-stride sequence of additional 4-byte
    -- addresses filling the remainder of the SvcParamValue.
    --
    decodeSPV _ len = do
        h  <- get32
        hs <- getFixedWidthSequence 4 get32 (len - 4)
        pure $ SVCParamValue $ SPV_EXT_IPV4HEX (h :| hs)

-- | Add our SVCB extension to a resolver configuration.
-- SVCB and HTTPS each carry their own copy of the SvcParam
-- codec map, so 'extendRRwithType' must be applied to
-- each separately.  On a key-codepoint conflict the
-- user-supplied type wins, with one exception: the reserved
-- @mandatory@ key (RFC 9460 section 8) is always preserved.
--
withIPv4Hex :: ResolverConf -> ResolverConf
withIPv4Hex = extendRRwithType T_svcb  SPV_ext_ipv4hex
            . extendRRwithType T_https SPV_ext_ipv4hex

-- | Complain and exit with an error.
--
bail :: String -> IO ()
bail why = hPutStrLn stderr why >> exitFailure

-- | Complain and keep going, producing a blank-line
-- terminated comment in place of the expected RRs.
--
carp :: Show a => String -> String -> a -> IO ()
carp what which why =
    putStrLn $ what ++ " '" ++ which ++ "': " ++ show why ++ "\n"

-- | For each domain in the command-line argument list look
-- up its @HTTPS@ records and print the results.  Any
-- @ipv4hint@ values in the responses will decode through
-- the app-defined hex type and present accordingly; any
-- non-@ipv4hint@ SvcParams in the same answer continue to
-- use their built-in decoders.
--
main :: IO ()
main = getArgs >>= \ case
    [] -> do
        prog <- getProgName
        bail $ "Usage: " ++ prog ++ " domain [...]"

    -- Build seed from extended resolver config
    args -> do
        let conf = withIPv4Hex defaultResolvConf
        makeResolvSeed conf >>= \ case
            Left why ->
                bail $ "Resolver configuration error: " ++ show why

            -- Instantiate the extended resolver once, and
            -- run one or more queries in sequence.  For
            -- parallel lookups separate per-thread resolvers
            -- need to be instantiated for each 'forkIO'
            -- /thread/ (typically from the same /seed/).
            --
            Right seed -> withResolver seed \ rslv -> runAll rslv args
  where
    runAll :: Resolver -> [String] -> IO ()
    runAll = mapM_ . runOne

    -- Retrieve and print the answer RRset.  With
    -- 'lookupAnswers' we get a full 'RR' wrapper around each
    -- record, including the owner name and the type's
    -- presentation-form name ("HTTPS"); custom SvcParam values
    -- inside each record are rendered through the app's
    -- 'Presentable' instance, so @ipv4hint@ values present
    -- in hex.
    --
    runOne rslv dom = case makeDomain8Str dom of
        Left why -> carp "; Error parsing" dom why
        Right dn ->
            -- Issue the query with default controls.
            --
            lookupAnswers rslv mempty IN HTTPS dn >>= \ case
                -- Handle SERVFAIL, timeouts, ...
                Left why -> carp "; Lookup error" dom why

                -- When no answers, output a diagnostic
                -- comment.
                --
                Right [] -> putBuilder $ present ';'
                    . presentSp dom . presentSp "HTTPS"
                    . presentSp "NODATA" $ presentLn '\n' mempty

                -- Otherwise one answer RR per line in
                -- presentation form followed by a blank
                -- line to terminate each complete answer
                -- RR set.
                --
                Right rs -> putBuilder $ foldr presentLn nl rs
              where
                -- The terminator newline.
                nl = present '\n' mempty
