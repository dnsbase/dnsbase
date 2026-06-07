{-# LANGUAGE
    OverloadedStrings
  , RecordWildCards
  , TypeApplications
  #-}
module Main (main) where

import Control.Monad.Trans.Except (ExceptT(..))
import Test.Tasty
import Test.Tasty.HUnit

import qualified Data.ByteString as B
import Data.ByteString.Short (ShortByteString)
import Data.Word (Word16)

import Net.DNSBase
import Net.DNSBase.Decode.Internal.Option (T_opt(..))
import Net.DNSBase.Decode.Internal.RData (getRData)
import Net.DNSBase.Resolver.Internal.Types (ResolvSeed(..))

----------------------------------------------------------------------
-- A custom RR-data type that overrides the library's built-in 'T_a'
-- at RRTYPE 1: decodes the four wire bytes verbatim into a
-- 'ShortByteString' instead of parsing them as an IPv4 address.

data T_ext_a = T_EXT_A ShortByteString
    deriving (Eq, Ord, Show)

instance Presentable T_ext_a where
    present _ = present @String "EXT_A"

instance KnownRData T_ext_a where
    rdType _ = A
    rdTypePres _ = present @String "EXT_A"
    rdEncode (T_EXT_A bs) = putShortByteString bs
    rdDecode _ _ = const $ RData . T_EXT_A <$> getShortNByteString 4

----------------------------------------------------------------------
-- A custom SVCB SvcParamValue type that overrides the library's
-- built-in @port@ key (codepoint 3): decodes the 16-bit value into
-- 'SPV_EXT_PORT' instead of 'SPV_PORT'.

data SPV_EXT_port = SPV_EXT_PORT Word16
    deriving (Eq, Ord, Show)

instance Presentable SPV_EXT_port where
    present (SPV_EXT_PORT p) = present @String "ext-port=" . present p

instance KnownSVCParamValue SPV_EXT_port where
    spvKey _ = SVCParamKey 3
    encodeSPV (SPV_EXT_PORT p) = put16 p
    decodeSPV _ _ = SVCParamValue . SPV_EXT_PORT <$> get16

----------------------------------------------------------------------

main :: IO ()
main = do
    (s1, s2, s3) <- getSeeds >>= either (fail . show) pure
    defaultMain $ testGroup "Extensibility"
        [ testCase "override built-in RRTYPE A"           (testOverrideRRtype s1)
        , testCase "override built-in SVCB port"          (testOverrideSvcParam s2)
        , testCase "override built-in EDE info-code name" (testOverrideEdeName s3)
        ]
  where
    ede0Name :: (Word16, ShortByteString)
    ede0Name = (0, "Custom Other Error")
    getSeeds = runDNSIO do
        s1 <- ExceptT (makeResolvSeed (registerRRtype T_ext_a defaultResolvConf))
        s2 <- ExceptT (makeResolvSeed (extendRRwithType T_svcb SPV_EXT_port defaultResolvConf))
        s3 <- ExceptT (makeResolvSeed (extendEdnsOptionWithValue O_ede ede0Name defaultResolvConf))
        pure (s1, s2, s3)

testOverrideRRtype :: ResolvSeed -> Assertion
testOverrideRRtype ResolvSeed {seedRDataMap = dm} = do
    case decodeAtWith 0 False (getRData dm Nothing 1 (B.length aWire)) aWire of
        Left err -> assertFailure $ "decode failed: " ++ show err
        Right rd -> case fromRData rd :: Maybe T_ext_a of
            Just _  -> pure ()
            Nothing -> assertFailure $
                "expected T_ext_a, got " ++ presentString rd mempty
  where
    -- | Wire form for the 4-byte A record @192.0.2.1@.
    aWire :: B.ByteString
    aWire = B.pack [0xC0, 0x00, 0x02, 0x01]

testOverrideSvcParam :: ResolvSeed -> Assertion
testOverrideSvcParam ResolvSeed {seedRDataMap = dm} = do
    case decodeAtWith 0 False (getRData dm Nothing 64 (B.length svcbWire)) svcbWire of
        Left err -> assertFailure $ "decode failed: " ++ show err
        Right rd -> case fromRData rd :: Maybe T_svcb of
            Nothing -> assertFailure $
                "expected T_svcb, got " ++ presentString rd mempty
            Just X_SVCB{..} ->
                case spvLookup @SPV_EXT_port x_svcParamValues of
                    Just (SPV_EXT_PORT 80) -> pure ()
                    Just (SPV_EXT_PORT p)  -> assertFailure $
                        "expected port 80, got " ++ show p
                    Nothing -> assertFailure $
                        "no SPV_EXT_port in "
                        ++ presentString x_svcParamValues mempty
  where
    -- | Wire form for a minimal SVCB record: priority 1, root target,
    -- one SvcParam (port = 80).
    svcbWire :: B.ByteString
    svcbWire = B.pack
        [ 0x00, 0x01   -- priority 1
        , 0x00         -- target = root
        , 0x00, 0x03   -- SvcParamKey port (3)
        , 0x00, 0x02   -- value length 2
        , 0x00, 0x50   -- port 80
        ]

testOverrideEdeName :: ResolvSeed -> Assertion
testOverrideEdeName ResolvSeed {seedRDataMap = dm, seedOptionMap = om} = do
    case decodeAtWith 0 False (getRData dm (Just om) 41 (B.length optEdeWire)) optEdeWire of
        Left err -> assertFailure $ "decode failed: " ++ show err
        Right rd -> case fromRData rd :: Maybe T_opt of
            Nothing -> assertFailure "expected T_opt for RRTYPE 41"
            Just (T_OPT opts) -> case monoOption @O_ede opts of
                [O_EDE 0 name ""] | name == "Custom Other Error" -> pure ()
                other -> assertFailure $ "wrong EDE list: " ++ show other
  where
    -- | Wire form for an OPT RDATA containing a single EDE option
    -- (option code 15, info-code 0, no extra text).
    optEdeWire :: B.ByteString
    optEdeWire = B.pack
        [ 0x00, 0x0F   -- EDE option code (15)
        , 0x00, 0x02   -- value length 2
        , 0x00, 0x00   -- info-code 0, no text
        ]
