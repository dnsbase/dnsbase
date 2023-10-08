{-# LANGUAGE
    OverloadedStrings
  , TemplateHaskell
  #-}
module Main (main) where

import qualified Data.Base16.Types as B16
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString as B
import qualified System.Exit as Sys

import Net.DNSBase.Domain
import Net.DNSBase.Message
import Net.DNSBase.Flags
import Net.DNSBase.EDNS
import Net.DNSBase.EDNS.Option
import Net.DNSBase.EDNS.Option.NSID
import Net.DNSBase.Opcode
import Net.DNSBase.RCODE
import Net.DNSBase.RR
import Net.DNSBase.RRCLASS
import Net.DNSBase.RRTYPE
import Net.DNSBase.RData
import Net.DNSBase.RData.A
import Net.DNSBase.RData.SRV


check :: (Show a, Eq a)
      => Either a B.ByteString
      -> Either a B.ByteString
      -> IO ()
check actual wanted = do
    if actual == wanted
    then pure ()
    else do putStrLn $ "Wanted: " ++ show wanted
            putStrLn $ "Actual: " ++ show actual
            Sys.exitWith $ Sys.ExitFailure 1

-- | Encode a query with given features via the request encoder.
mkReq :: Domain
      -> RRTYPE
      -> DNSFlags
      -> Maybe EDNS
      -> Either (EncodeErr (Maybe RData)) B.ByteString
mkReq qname qtype flags edns =
    fmap (B16.extractBase16 . B16.encodeBase16')
    $ encodeVerbatim
    $ putRequest 0xbeef flags edns (DnsTriple qname qtype IN)


-- | Encode a query with given features via the generic encoder.
mkQuery :: Domain
        -> RRTYPE
        -> RCODE
        -> DNSFlags
        -> Maybe EDNS
        -> Either (EncodeErr (Maybe RData)) B.ByteString
mkQuery qname qtype rc flags edns =
    fmap (B16.extractBase16 . B16.encodeBase16')
    $ encodeVerbatim
    $ putMessage
    $ DNSMessage 0xbeef Query rc flags edns
                 [DnsTriple qname qtype IN]
                 [] [] []

-- | Create a response message with given features and name compression
mkAnswer :: Domain
         -> RRTYPE
         -> RCODE
         -> DNSFlags
         -> Maybe EDNS
         -> [RR]
         -> [RR]
         -> [RR]
         -> Either (EncodeErr (Maybe RData)) B.ByteString
mkAnswer qname qtype rc flags edns an ns ar =
    fmap (B16.extractBase16 . B16.encodeBase16')
    $ encodeCompressed
    $ putMessage
    $ DNSMessage 0xbeef Query rc (QRflag <> flags) edns
                 [DnsTriple qname qtype IN]
                 an ns ar


main :: IO ()
main = do
    let rdad = RDflag <> ADflag
    -- Minimal legacy query
    check (mkReq $$(dnLit "example.com") MX rdad Nothing) $
        Right $ "beef0120"         -- header
             <> "00010000"         -- qdcount, ancount
             <> "00000000"         -- nscount, arcount
             <> "076578616d706c65" -- "example."
             <> "03636f6d00"       -- "com."
             <> "000f0001"         -- MX IN

    -- Minimal EDNS query
    check (mkReq $$(dnLit "example.com") MX rdad (Just defaultEDNS)) $
        Right $ "beef0120"         -- header
             <> "00010000"         -- qdcount, ancount
             <> "00000001"         -- nscount, arcount
             <> "076578616d706c65" -- "example."
             <> "03636f6d00"       -- "com."
             <> "000f0001"         -- MX IN
             <> "000029"           -- . OPT
             <> "04d0"             -- buffer size 1232
             <> "0000"             -- extRCODE=0 ednsVERSION=0
             <> "00000000"         -- Flags=0x0000, RDLEN=0

    -- EDNS with NSID option
    let nsid = SomeOption $ O_NSID ""
        edns = defaultEDNS { ednsOptions = [nsid] }
        dord = DOflag <> RDflag
    check (mkReq $$(dnLit "example.com") MX dord (Just edns)) $
        Right $ "beef0100"         -- header
             <> "00010000"         -- qdcount, ancount
             <> "00000001"         -- nscount, arcount
             <> "076578616d706c65" -- "example."
             <> "03636f6d00"       -- "com."
             <> "000f0001"         -- MX IN
             <> "000029"           -- . OPT
             <> "04d0"             -- buffer size 1232
             <> "0000"             -- extRCODE=0 ednsVERSION=0
             <> "80000004"         -- Flags=DO, RDLEN=4
             <> "00030000"         -- NSID, length 0

    -- Extended rcode with EDNS disabled
    check (mkReq $$(dnLit "example.com") MX (rdad <> DOflag) Nothing) $
        Left EDNSRequired

    -- Extended flags with EDNS disabled
    check (mkQuery $$(dnLit "example.com") MX BADVERS rdad Nothing) $
        Left EDNSRequired

    -- Extended RCODE and flags with EDNS enabled
    check (mkQuery $$(dnLit "example.com") MX BADVERS (rdad <> DOflag) (Just defaultEDNS)) $
        Right $ "beef0120"         -- header
             <> "00010000"         -- qdcount, ancount
             <> "00000001"         -- nscount, arcount
             <> "076578616d706c65" -- "example."
             <> "03636f6d00"       -- "com."
             <> "000f0001"         -- MX IN
             <> "000029"           -- . OPT
             <> "04d0"             -- buffer size 1232
             <> "0100"             -- extRCODE=1 ednsVERSION=0
             <> "80000000"         -- Flags=0x8000, RDLEN=0

    -- EDNS answer with name compression
    let rdraad = RDflag <> RAflag <> ADflag
    check (mkAnswer $$(dnLit "example.com") MX NOERROR rdraad (Just defaultEDNS)
           [ RR $$(dnLit "example.com") IN 300
                $ RData $ T_MX 10 $$(dnLit "mx1.example.com")
           , RR $$(dnLit "example.com") IN 300
                $ RData $ T_MX 10 $$(dnLit "mx2.example.com") ]
           []
           [ RR $$(dnLit "mx1.example.com") IN 300
                $ RData $ T_A "192.0.2.1"
           , RR $$(dnLit "mx2.example.com") IN 300
                $ RData $ T_A "192.0.2.2" ]
        ) $
        Right $ "beef81a0"         -- 0. header
             <> "00010002"         -- 4. qdcount, ancount
             <> "00000003"         -- 8. nscount, arcount
             --
             <> "076578616d706c65" -- 12. "example."
             <> "03636f6d00"       -- 20. "com."
             <> "000f0001"         -- 25. MX IN
             --
             <> "c00c"             -- 29. "example.com" compressed
             <> "000f0001"         -- 31. MX IN
             <> "0000012c"         -- 35. TTL = 300
             <> "0008"             -- 39. RDLEN = 8
             <> "000a"             -- 41. pref = 10
             <> "036d7831c00c"     -- 43. exch = "mx1.example.com" compressed
             --
             <> "c00c"             -- 49. "example.com" compressed
             <> "000f0001"         -- 51. MX IN
             <> "0000012c"         -- 55. TTL = 300
             <> "0008"             -- 59. RDLEN = 8
             <> "000a"             -- 61. pref = 10
             <> "036d7832c00c"     -- 63. exch = "mx2.example.com" compressed
             --
             <> "000029"           -- 69. . OPT
             <> "04d0"             -- 72. buffer size 1232
             <> "0000"             -- 74. extRCODE=0 ednsVERSION=0
             <> "00000000"         -- 76. Flags=0x0000, RDLEN=0
             --
             <> "c02b"             -- 80. "mx1.example.com" compressed
             <> "00010001"         -- 82. A IN
             <> "0000012c"         -- 86. TTL = 300
             <> "0004"             -- 90. RDLEN = 4
             <> "c0000201"         -- 92. 192.0.2.1
             --
             <> "c03f"             -- 96. "mx2.example.com" compressed
             <> "00010001"         -- 98. A IN
             <> "0000012c"         -- 102. TTL = 300
             <> "0004"             -- 106. RDLEN = 4
             <> "c0000202"         -- 108. 192.0.2.2
