{-# LANGUAGE
    CPP
  , OverloadedStrings
  , OverloadedLists
  , RecordWildCards
  , TemplateHaskell
  #-}
module Main where

import Test.Tasty
import Test.Tasty.QuickCheck hiding ((.&.))

import qualified Data.ByteString as B
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as LC
import qualified Data.ByteString.Short as SB
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Text.Unsafe as T
import Data.IP (Addr(..))
#if MIN_VERSION_base(4,17,0)
import GHC.IsList(IsList(..))
#else
import GHC.Exts(IsList(..))
#endif

-- getRR and getMessage are not public APIs, nor rdataEncodeCanonical
import Net.DNSBase.Decode.Internal.Message (getMessage)
import Net.DNSBase.Decode.Internal.RData
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.Util
import Net.DNSBase.Resolver.Internal.Types

import Net.DNSBase
import Net.DNSBase.Nat16
import Net.DNSBase.RData.Obsolete

baseCodecs :: RDataMap
baseCodecs = rcRDataMap defaultResolvConf

baseOptions :: OptionMap
baseOptions = rcOptnMap defaultResolvConf

main :: IO ()
main = defaultMain $ testGroup "Main"
    [ textTests
    , vectorTests
    , rdataTests
    , canonEqTests
    , canonOrdTests
    , ednsTests
    ]
  where
    textTests :: TestTree
    textTests = testGroup "Prerequisite UTF8 support" [ testUtf8 ]

    vectorTests :: TestTree
    vectorTests = testGroup "Presentation and wire test vectors" (testVec <$> testVectors)

    rdataTests :: TestTree
    rdataTests = testGroup "RData codec round-trip tests" (rdgens testRData)

    canonEqTests :: TestTree
    canonEqTests = testGroup "Decoding canonical encoding equal to input" (rdgens testCnEq)

    canonOrdTests :: TestTree
    canonOrdTests = testGroup "RData Ord is canonical" (rdgens testCnOrd)

    ednsTests :: TestTree
    ednsTests = testGroup "EDNS option codec round-trip tests" optgens

    optgens =
        [ testOption ECS  genECS
        , testOption NSID genNSID
        , testOption DAU  genDAU
        , testOption DHU  genDHU
        , testOption N3U  genN3U
        , testOption 0    genOpaqueOpt ]

    rdgens f =
        [ f A          genA
        , f NS         genNS
        , f MD         genMD
        , f MF         genMF
        , f CNAME      genCNAME
        , f SOA        genSOA
        , f MB         genMB
        , f MG         genMG
        , f MR         genMR
        , f NULL       genNULL
        , f WKS        genWKS
        , f PTR        genPTR
        , f HINFO      genHINFO
        , f MINFO      genMINFO
        , f MX         genMX
        , f TXT        genTXT
        , f RP         genRP
        , f AFSDB      genAFSDB
        , f X25        genX25
        , f ISDN       genISDN
        , f RT         genRT
        , f NSAP       genNSAP
        , f NSAPPTR    genNSAPPTR
        , f SIG        genSIG
        , f KEY        genKEY
        , f PX         genPX
        , f GPOS       genGPOS
        , f AAAA       genAAAA
        , f NXT        genNXT
        , f SRV        genSRV
        , f NAPTR      genNAPTR
        , f KX         genKX
        , f A6         genA6
        , f DNAME      genDNAME
        , f DS         genDS
        , f SSHFP      genSSHFP
        , f RRSIG      genRRSIG
        , f NSEC       genNSEC
        , f DNSKEY     genDNSKEY
        , f NSEC3      genNSEC3
        , f NSEC3PARAM genNSEC3PARAM
        , f TLSA       genTLSA
        , f CDS        genCDS
        , f CDNSKEY    genCDNSKEY
        , f ZONEMD     genZONEMD
        , f SVCB       genSVCB
        , f HTTPS      genHTTPS
        , f CAA        genCAA
        , f CSYNC      genCSYNC
        , f (RRTYPE 0xfeed) (genOpaque 0xfeed)
        ]

testVec ::  (RR, LB.ByteString, Bytes16) -> TestTree
testVec (rr, pform, wform) =
    testProperty testName $
        if (gotp /= pform)
        then error $ "RR: " ++ show rr ++
                ",\nPresentation form delta:\nhave:\t" ++ LC.unpack gotp ++
                "\nwant:\t" ++ LC.unpack pform
        else case gotw of
            Left err -> error $ "Failed to encode: " ++ show rr ++ ", reason: " ++ show err
            Right bs | bs /= wform ->
                        error $ "RR: " ++ show rr ++
                            ",\nWire form delta:\nhave:\t" ++ show bs ++
                            "\nwant:\t" ++ show wform
                     | otherwise -> True
  where
    typeName = case rrData rr of
        RData (_ :: t) -> show $ rdTypePres t mempty
    testName = presentString typeName " presentation and wire form test vector"
    gotp = presentLazy rr mempty
    gotw = Bytes16 . SB.toShort <$> encodeCompressed (putRR rr)

testVectors :: [ (RR, LB.ByteString, Bytes16) ]
testVectors =
    [ ( mkRR zone $ T_A "192.0.2.1"
      , "example.org. 300 IN A 192.0.2.1"
      , "076578616d706c65036f726700"
        <> "0001" <> "0001" <> "0000012c" <> "0004"
        <> "c0000201"
      )
    , ( mkRR zone $ T_NS $$(dnLit "nsa.example.org")
      , "example.org. 300 IN NS nsa.example.org."
      , "076578616d706c65036f726700"
        <> "0002" <> "0001" <> "0000012c" <> "0006"
        <> "036e7361c000"
      )
    , ( mkRR zone $ T_MD $$(dnLit "madname.example.org")
      , "example.org. 300 IN MD madname.example.org."
      , "076578616d706c65036f726700"
        <> "0003" <> "0001" <> "0000012c" <> "000a"
        <> "076d61646e616d65c000"
      )
    , ( mkRR zone $ T_MF $$(dnLit "madname.example.org")
      , "example.org. 300 IN MF madname.example.org."
      , "076578616d706c65036f726700"
        <> "0004" <> "0001" <> "0000012c" <> "000a"
        <> "076d61646e616d65c000"
      )
    , ( mkRR zone $ T_CNAME $$(dnLit "cname.example.org")
      , "example.org. 300 IN CNAME cname.example.org."
      , "076578616d706c65036f726700"
        <> "0005" <> "0001" <> "0000012c" <> "0008"
        <> "05636e616d65c000"
      )
    , ( mkRR zone $ T_SOA $$(dnLit "dns.example.org") $$(mbLit "postmaster@dns.example.org") 2023111301 1800 900 604800 86400
      , "example.org. 300 IN SOA dns.example.org. postmaster.dns.example.org. 2023111301 1800 900 604800 86400"
      , "076578616d706c65036f726700"
        <> "0006" <> "0001" <> "0000012c" <> "0027"
        <> "03646e73c000" <> "0a706f73746d6173746572c017"
        <> "78963a85" <> "00000708" <> "00000384" <> "00093a80" <> "00015180"
      )
    , ( mkRR zone $ T_MB $$(dnLit "madname.example.org")
      , "example.org. 300 IN MB madname.example.org."
      , "076578616d706c65036f726700"
        <> "0007" <> "0001" <> "0000012c" <> "000a"
        <> "076d61646e616d65c000"
      )
    , ( mkRR zone $ T_MG $$(mbLit "some.name@example.org")
      , "example.org. 300 IN MG some\\.name.example.org."
      , "076578616d706c65036f726700"
        <> "0008" <> "0001" <> "0000012c" <> "000c"
        <> "09736f6d652e6e616d65c000"
      )
    , ( mkRR zone $ T_MR $$(mbLit "other.name@example.org")
      , "example.org. 300 IN MR other\\.name.example.org."
      , "076578616d706c65036f726700"
        <> "0009" <> "0001" <> "0000012c" <> "000d"
        <> "0a6f746865722e6e616d65c000"
      )
    , ( mkRR zone $ T_NULL "feedcafedeadbeef"
      , "example.org. 300 IN NULL \\# 8 feedcafedeadbeef"
      , "076578616d706c65036f726700"
        <> "000a" <> "0001" <> "0000012c" <> "0008"
        <> "feedcafedeadbeef"
      )
    , ( mkRR zone $ T_WKS "192.0.2.1" UDP [53]
      , "example.org. 300 IN WKS 192.0.2.1 UDP ( 53 )"
      , "076578616d706c65036f726700"
        <> "000b" <> "0001" <> "0000012c" <> "000c"
        <> "c0000201" <> "11" <> "00000000000004"
      )
    , ( mkRR zone $ T_PTR $$(mbLit "ptr.example.org")
      , "example.org. 300 IN PTR ptr.example.org."
      , "076578616d706c65036f726700"
        <> "000c" <> "0001" <> "0000012c" <> "0006"
        <> "03707472c000"
      )
    , ( mkRR zone $ T_HINFO "Some\tCPU" "Some \\ OS"
      , "example.org. 300 IN HINFO \"Some\\009CPU\" \"Some \\\\ OS\""
      , "076578616d706c65036f726700"
        <> "000d" <> "0001" <> "0000012c" <> "0013"
        <> "08536f6d650943505509536f6d65205c204f53"
      )
    , ( mkRR zone $ T_MINFO $$(mbLit "list-request.example.org")
                           $$(mbLit "owner-list.example.org")
      , "example.org. 300 IN MINFO list-request.example.org." <>
        " owner-list.example.org."
      , "076578616d706c65036f726700"
        <> "000e" <> "0001" <> "0000012c" <> "001c"
        <> "0c6c6973742d72657175657374c000"
        <> "0a6f776e65722d6c697374c000"
      )
    , ( mkRR zone $ T_MX 10 $$(dnLit "mx1.example.org")
      , "example.org. 300 IN MX 10 mx1.example.org."
      , "076578616d706c65036f726700"
        <> "000f" <> "0001" <> "0000012c" <> "0008"
        <> "000a" <> "036d7831c000"
      )
    , ( mkRR zone $ T_TXT [ "The \"quick\" brown fox",
                           " jumped over the lazy dog\n" ]
      , "example.org. 300 IN TXT \"The \\\"quick\\\" brown fox\"" <>
        " \" jumped over the lazy dog\\010\""
      , "076578616d706c65036f726700"
        <> "0010" <> "0001" <> "0000012c" <> "0031"
        <> "155468652022717569636b222062726f776e20666f78"
        <> "1a206a756d706564206f76657220746865206c617a7920646f670a"
      )
    , ( mkRR zone $ T_RP $$(mbLit "noc@example.org") $$(dnLit "contact.example.org")
      , "example.org. 300 IN RP noc.example.org. contact.example.org."
      , "076578616d706c65036f726700"
        <> "0011" <> "0001" <> "0000012c" <> "0026"
        <> "036e6f63076578616d706c65036f726700"
        <> "07636f6e74616374076578616d706c65036f726700"
      )
    , ( mkRR zone $ T_AFSDB 12345 $$(dnLit "voldb.example.org")
      , "example.org. 300 IN AFSDB 12345 voldb.example.org."
      , "076578616d706c65036f726700"
        <> "0012" <> "0001" <> "0000012c" <> "0015"
        <> "3039"
        <> "05766f6c6462076578616d706c65036f726700"
      )
    , ( mkRR zone $ T_X25 "1234567890"
      , "example.org. 300 IN X25 \"1234567890\""
      , "076578616d706c65036f726700"
        <> "0013" <> "0001" <> "0000012c" <> "000b"
        <> "0a31323334353637383930"
      )
    , ( mkRR zone $ T_ISDN "1234567890" Nothing
      , "example.org. 300 IN ISDN \"1234567890\""
      , "076578616d706c65036f726700"
        <> "0014" <> "0001" <> "0000012c" <> "000b"
        <> "0a31323334353637383930"
      )
    , ( mkRR zone $ T_ISDN "1234567890" (Just "beef")
      , "example.org. 300 IN ISDN \"1234567890\" \"beef\""
      , "076578616d706c65036f726700"
        <> "0014" <> "0001" <> "0000012c" <> "0010"
        <> "0a31323334353637383930"
        <> "0462656566"
      )
    , ( mkRR zone $ T_RT 12345 $$(dnLit "route1.example.org")
      , "example.org. 300 IN RT 12345 route1.example.org."
      , "076578616d706c65036f726700"
        <> "0015" <> "0001" <> "0000012c" <> "0016"
        <> "3039"
        <> "06726f75746531076578616d706c65036f726700"
      )
    , ( mkRR zone $ T_NSAP (coerce @Bytes16 "01e13708002010726e00")
      , "example.org. 300 IN NSAP 0x01e13708002010726e00"
      , "076578616d706c65036f726700"
        <> "0016" <> "0001" <> "0000012c" <> "000a"
        <> "01e13708002010726e00"
      )
    , ( mkRR zone $ T_NSAPPTR zone
      , "example.org. 300 IN NSAP-PTR example.org."
      , "076578616d706c65036f726700"
        <> "0017" <> "0001" <> "0000012c" <> "000d"
        <> "076578616d706c65036f726700"
      )
    , ( mkRR zone $ T_SIG NS 13 1 172800 (coerce @Epoch64 "20231120081211")
                                         (coerce @Epoch64 "20231113070211")
                                         44222 zone sigbytes
      , "example.org. 300 IN SIG NS 13 1 172800 20231120081211 20231113070211 44222 example.org. "
        <> sigchars
      , "076578616d706c65036f726700"
        <> "0018" <> "0001" <> "0000012c" <> "005f"
        <> "0002" <> "0d" <> "01" <> "0002a300"
        <> "655b14db" <> "6551c9f3" <> "acbe"
        <> "076578616d706c65036f726700"
        <> sighex
      )
    , ( mkRR zone $ T_KEY 257 3 13 keybytes
      , "example.org. 300 IN KEY 257 3 13 " <> keychars
      , "076578616d706c65036f726700"
        <> "0019" <> "0001" <> "0000012c" <> "0044"
        <> "0101" <> "03" <> "0d" <> keyhex
      )
    , ( mkRR zone $ T_PX 12345 zone zone
      , "example.org. 300 IN PX 12345 example.org. example.org."
      , "076578616d706c65036f726700"
        <> "001a" <> "0001" <> "0000012c" <> "001c"
        <> "3039"
        <> "076578616d706c65036f726700"
        <> "076578616d706c65036f726700"
      )
    , ( mkRR zone $ T_GPOS "-32.6882" "116.8652" "10.0"
      , "example.org. 300 IN GPOS \"-32.6882\" \"116.8652\" \"10.0\""
      , "076578616d706c65036f726700"
        <> "001b" <> "0001" <> "0000012c" <> "0017"
        <> "082d33322e36383832"
        <> "083131362e38363532"
        <> "0431302e30"
      )
    , ( mkRR zone $ T_AAAA "::192.0.2.1"
      , "example.org. 300 IN AAAA ::192.0.2.1"
      , "076578616d706c65036f726700"
        <> "001c" <> "0001" <> "0000012c" <> "0010"
        <> "000000000000000000000000c0000201"
      )
    , ( mkRR zone $ T_NXT $$(dnLit "*.example.org") (toNxtTypes $ NS :| [SOA, KEY, SIG])
      , "example.org. 300 IN NXT *.example.org. NS SOA SIG KEY NXT"
      , "076578616d706c65036f726700"
        <> "001e" <> "0001" <> "0000012c" <> "0013"
        <> "012a076578616d706c65036f726700"
        <> "220000c2"
      )
    , ( mkRR zone $ T_SRV 2000 300 4443 $$(dnLit "www.example.org")
      , "example.org. 300 IN SRV 2000 300 4443 www.example.org."
      , "076578616d706c65036f726700"
        <> "0021" <> "0001" <> "0000012c" <> "0017"
        <> "07d0" <> "012c" <> "115b"
        <> "03777777076578616d706c65036f726700"
      )
    , ( mkRR zone $ T_NAPTR 100 10 "" "" "!^urn:cid:.+@([^\\.]+\\.)(.*)$!\\2!i" RootDomain
      , "example.org. 300 IN NAPTR 100 10 \"\" \"\" \"!^urn:cid:.+@([^\\\\.]+\\\\.)(.*)$!\\\\2!i\" ."
      , "076578616d706c65036f726700"
        <> "0023" <> "0001" <> "0000012c" <> "0029"
        <> "0064" <> "000a" <> "00" <> "00"
        <> "21215e75726e3a6369643a2e2b40285b5e5c2e5d2b5c2e29282e2a2924215c322169"
        <> "00"
      )
    , ( mkRR zone $ T_KX 12345 $$(dnLit "kx.example.org")
      , "example.org. 300 IN KX 12345 kx.example.org."
      , "076578616d706c65036f726700"
        <> "0024" <> "0001" <> "0000012c" <> "0012"
        <> "3039" <> "026b78076578616d706c65036f726700"
      )
    , ( mkRR zone $ T_A6 0 "::1" Nothing
      , "example.org. 300 IN A6 0 ::1"
      , "076578616d706c65036f726700"
        <> "0026" <> "0001" <> "0000012c" <> "0011"
        <> "00" <> "00000000000000000000000000000001"
      )
    , ( mkRR zone $ T_A6 128 "::" (Just zone)
      , "example.org. 300 IN A6 128 :: example.org."
      , "076578616d706c65036f726700"
        <> "0026" <> "0001" <> "0000012c" <> "000e"
        <> "80" <> "076578616d706c65036f726700"
      )
    , ( mkRR zone $ T_A6 32 "::192.0.2.1" (Just zone)
      , "example.org. 300 IN A6 32 ::192.0.2.1 example.org."
      , "076578616d706c65036f726700"
        <> "0026" <> "0001" <> "0000012c" <> "001a"
        <> "20" <> "0000000000000000c0000201"
        <> "076578616d706c65036f726700"
      )
    , ( mkRR zone $ T_DNAME $$(dnLit "sample.org.")
      , "example.org. 300 IN DNAME sample.org."
      , "076578616d706c65036f726700"
        <> "0027" <> "0001" <> "0000012c" <> "000c"
        <> "0673616d706c65036f726700"
      )
    , ( mkRR zone $ T_DS 37331 13 2 shabytes
      , "example.org. 300 IN DS 37331 13 2 " <> shachars
      , "076578616d706c65036f726700"
        <> "002b" <> "0001" <> "0000012c" <> "0024"
        <> "91d3" <> "0d" <> "02" <> shahex
      )
    , ( mkRR zone $ T_SSHFP 4 2 sshkeybytes
      , "example.org. 300 IN SSHFP 4 2 " <> sshkeychars
      , "076578616d706c65036f726700"
        <> "002c" <> "0001" <> "0000012c" <> "0022"
        <> "04" <> "02" <> sshkeyhex
      )
    , ( mkRR zone $ T_RRSIG NS 13 1 172800 (coerce @Epoch64 "20231120081211")
                                           (coerce @Epoch64 "20231113070211")
                                           44222 zone sigbytes
      , "example.org. 300 IN RRSIG NS 13 1 172800 20231120081211 20231113070211 44222 example.org. "
        <> sigchars
      , "076578616d706c65036f726700"
        <> "002e" <> "0001" <> "0000012c" <> "005f"
        <> "0002" <> "0d" <> "01" <> "0002a300"
        <> "655b14db" <> "6551c9f3" <> "acbe"
        <> "076578616d706c65036f726700"
        <> sighex
      )
    , ( mkRR zone $ T_NSEC $$(dnLit "*.example.org") [ NS, SOA, DNSKEY, NSEC
                                                    , RRSIG, CAA ]
      , "example.org. 300 IN NSEC *.example.org. NS SOA RRSIG NSEC DNSKEY CAA"
      , "076578616d706c65036f726700"
        <> "002f" <> "0001" <> "0000012c" <> "001b"
        <> "012a076578616d706c65036f726700"
        <> "000722000000000380010140"
      )
    , ( mkRR zone $ T_DNSKEY 257 3 13 keybytes
      , "example.org. 300 IN DNSKEY 257 3 13 " <> keychars
      , "076578616d706c65036f726700"
        <> "0030" <> "0001" <> "0000012c" <> "0044"
        <> "0101" <> "03" <> "0d" <> keyhex
      )
    , ( mkRR zone $ T_NSEC3 1 0 0 nsec3salt nsec3next [ NS, SOA, MX, TXT, DNSKEY
                                                     , NSEC, RRSIG, CAA ]
      , "example.org. 300 IN NSEC3 1 0 0 " <> saltchars <> " "
        <> nextchars <> " NS SOA MX TXT RRSIG NSEC DNSKEY CAA"
      , "076578616d706c65036f726700"
        <> "0032" <> "0001" <> "0000012c" <> "002a"
        <> "01" <> "00" <> "0000" <> salthex
        <> nexthex
        <> "000722018000000380010140"
      )
    , ( mkRR zone $ T_NSEC3PARAM 1 0 0 ""
      , "example.org. 300 IN NSEC3PARAM 1 0 0 -"
      , "076578616d706c65036f726700"
        <> "0033" <> "0001" <> "0000012c" <> "0005"
        <> "01" <> "00" <> "0000" <> "00"
      )
    , ( mkRR zone $ T_TLSA 3 1 1 tlsabytes
      , "example.org. 300 IN TLSA 3 1 1 " <> tlsachars
      , "076578616d706c65036f726700"
        <> "0034" <> "0001" <> "0000012c" <> "0023"
        <> "03" <> "01" <> "01" <> tlsahex
      )
    , ( mkRR zone $ T_CDS 0 0 0 (coerce @Bytes16 "00")
      , "example.org. 300 IN CDS 0 0 0 00"
      , "076578616d706c65036f726700"
        <> "003b" <> "0001" <> "0000012c" <> "0005"
        <> "0000" <> "00" <> "00" <> "00"
      )
    , ( mkRR zone $ T_CDNSKEY 0 3 0 (coerce @Bytes64 "AA==")
      , "example.org. 300 IN CDNSKEY 0 3 0 AA=="
      , "076578616d706c65036f726700"
        <> "003c" <> "0001" <> "0000012c" <> "0005"
        <> "0000" <> "03" <> "00" <> "00"
      )
    , ( mkRR zone $ T_CSYNC 66 3 [ A, NS, AAAA ]
      , "example.org. 300 IN CSYNC 66 3 A NS AAAA"
      , "076578616d706c65036f726700"
        <> "003e" <> "0001" <> "0000012c" <> "000c"
        <> "00000042" <> "0003" <> "000460000008"
      )
    , ( mkRR zone $ T_ZONEMD 2023111301 1 241 zmdbytes
      , "example.org. 300 IN ZONEMD 2023111301 1 241 " <> zmdchars
      , "076578616d706c65036f726700"
        <> "003f" <> "0001" <> "0000012c" <> "0036"
        <> "78963a85" <> "01" <> "f1" <> zmdhex
      )
    , ( mkRR zone $ T_SVCB 0 $$(dnLit "www.example.org") []
      , "example.org. 300 IN SVCB 0 www.example.org."
      , "076578616d706c65036f726700"
        <> "0040" <> "0001" <> "0000012c" <> "0013"
        <> "0000" <> "03777777076578616d706c65036f726700"
      )
    , ( mkRR zone $ T_SVCB 1 RootDomain []
      , "example.org. 300 IN SVCB 1 ."
      , "076578616d706c65036f726700"
        <> "0040" <> "0001" <> "0000012c" <> "0003"
        <> "0001" <> "00"
      )
    , ( mkRR zone $ T_SVCB 1 $$(dnLit "www.example.org")
                    [ SVCParamValue $ SPV_IPV6HINT $ ne ["2001:db8::1", "2001:db8::53:1"] ]
      , "example.org. 300 IN SVCB 1 www.example.org. ipv6hint=2001:db8::1,2001:db8::53:1"
      , "076578616d706c65036f726700"
        <> "0040" <> "0001" <> "0000012c" <> "0037"
        <> "0001" <> "03777777076578616d706c65036f726700"
        <> "0006" <> "0020" <> "20010db8000000000000000000000001"
                            <> "20010db8000000000000000000530001"
      )
    , ( mkRR zone $ T_SVCB 1 $$(dnLit "www.example.org")
                    [ opaqueSPV 667 "" ]
      , "example.org. 300 IN SVCB 1 www.example.org. key667"
      , "076578616d706c65036f726700"
        <> "0040" <> "0001" <> "0000012c" <> "0017"
        <> "0001" <> "03777777076578616d706c65036f726700"
        <> "029b" <> "0000"
      )
    , ( mkRR zone $ T_SVCB 1 $$(dnLit "www.example.org")
                    [ opaqueSPV 667 "hello" ]
      , "example.org. 300 IN SVCB 1 www.example.org. key667=\"hello\""
      , "076578616d706c65036f726700"
        <> "0040" <> "0001" <> "0000012c" <> "001c"
        <> "0001" <> "03777777076578616d706c65036f726700"
        <> "029b" <> "0005" <> "68656c6c6f"
      )
    , ( mkRR zone $ T_HTTPS 1 $$(dnLit "www.example.org")
                    [ opaqueSPV 667 "hello\210\&qoo" ]
      , "example.org. 300 IN HTTPS 1 www.example.org. key667=\"hello\\210qoo\""
      , "076578616d706c65036f726700"
        <> "0041" <> "0001" <> "0000012c" <> "0020"
        <> "0001" <> "03777777076578616d706c65036f726700"
        <> "029b" <> "0009" <> "68656c6c6fd2716f6f"
      )
    , ( mkRR zone $ T_HTTPS 16 $$(dnLit "www.example.org")
                    [ SVCParamValue $ SPV_ALPN $ ne ["f\\oo,bar", "h2"] ]
      , "example.org. 300 IN HTTPS 16 www.example.org. alpn=" <> alpn1
      , "076578616d706c65036f726700"
        <> "0041" <> "0001" <> "0000012c" <> "0023"
        <> "0010" <> "03777777076578616d706c65036f726700"
        <> "0001" <> "000c" <> "08" <> "665c6f6f2c626172"
                            <> "02" <> "6832"
      )
    , ( mkRR zone $ T_HTTPS 16 $$(dnLit "www.example.org")
                    [ SVCParamValue $ SPV_ALPN $ ne ["f\\oo,bar\"", "h2"] ]
      , "example.org. 300 IN HTTPS 16 www.example.org. alpn=" <> alpn2
      , "076578616d706c65036f726700"
        <> "0041" <> "0001" <> "0000012c" <> "0024"
        <> "0010" <> "03777777076578616d706c65036f726700"
        <> "0001" <> "000d" <> "09" <> "665c6f6f2c62617222"
                            <> "02" <> "6832"
      )
    , ( mkRR zone $ T_HTTPS 16 $$(dnLit "www.example.org")
                    [ SVCParamValue $ ne @SPV_mandatory [ALPN, IPV4HINT]
                    , SVCParamValue $ SPV_ALPN $ ne ["h2", "h3-19"]
                    , SVCParamValue $ SPV_IPV4HINT $ ne ["192.0.2.1"] ]
      , "example.org. 300 IN HTTPS 16 www.example.org."
         <> " mandatory=alpn,ipv4hint"
         <> " alpn=\"h2,h3-19\""
         <> " ipv4hint=192.0.2.1"
      , "076578616d706c65036f726700"
        <> "0041" <> "0001" <> "0000012c" <> "0030"
        <> "0010" <> "03777777076578616d706c65036f726700"
        <> "0000" <> "0004" <> "0001" <> "0004"
        <> "0001" <> "0009" <> "02" <> "6832"
                            <> "05" <> "68332d3139"
        <> "0004" <> "0004" <> "c0000201"
      )
    , ( mkRR zone $ T_HTTPS 16 $$(dnLit "www.example.org")
                    [ SVCParamValue $ SPV_PORT 53 ]
      , "example.org. 300 IN HTTPS 16 www.example.org. port=53"
      , "076578616d706c65036f726700"
        <> "0041" <> "0001" <> "0000012c" <> "0019"
        <> "0010" <> "03777777076578616d706c65036f726700"
        <> "0003" <> "0002" <> "0035"
      )
    , ( mkRR zone $ OpaqueRData @N_a $ coerce @Bytes16 "feedcafe"
      , "example.org. 300 IN TYPE1 \\# 4 feedcafe"
      , "076578616d706c65036f726700"
        <> "0001" <> "0001" <> "0000012c" <> "0004"
        <> "feedcafe"
      )
    ]
  where
    ne :: IsNonEmptyList b => [Item1 b] -> b
    ne = fromNonEmptyList . fromList

    b, c, d :: String
    b = ['\\']
    c = b <> ","
    d = ['"']
    alpn1, alpn2 :: LC.ByteString
    alpn1 = LC.pack . show $ "f" <> b <> b <> "oo" <> c <> "bar,h2"
    alpn2 = LC.pack . show $ "f" <> b <> b <> "oo" <> c <> "bar" <> d <> ",h2"

    zone :: Domain
    zone = $$(dnLit "example.org")

    mkRR :: KnownRData a => Domain -> a -> RR
    mkRR = \ owner -> RR owner IN 300 . RData

    salthex :: Bytes16
    salthex = "04" <> "feedcafe"
    nsec3salt :: ShortByteString
    nsec3salt = coerce @Bytes16 "feedcafe"
    saltchars :: LC.ByteString
    saltchars = "feedcafe"

    nexthex :: Bytes16
    nexthex = "14" <> "ada6735ee74b256dfcb46cc81c61f35c637c3160"
    nsec3next :: ShortByteString
    nsec3next = coerce @Bytes32 "LMJ76NN79CIMRV5KDJ41OOFJBHHNOCB0"
    nextchars :: LC.ByteString
    nextchars = "LMJ76NN79CIMRV5KDJ41OOFJBHHNOCB0"

    shahex   :: Bytes16
    shahex   = "2f0bec2d6f79dfbd1d08fd21a3af92d0e39a4b9ef1e3f4111fff282490da453b"
    shabytes :: ShortByteString
    shabytes = coerce @Bytes16 shahex
    shachars :: LC.ByteString
    shachars = "2f0bec2d6f79dfbd1d08fd21a3af92d0e39a4b9ef1e3f4111fff282490da453b"

    keyhex :: Bytes16
    keyhex = "1e20681a9cc344082b0e65175d34a797b8c25fa1f1e5bce45368d2c4c6d5234d" <>
             "724bed771323a08670a27415d4d1b1f6822db0f4685819a72953a0abb70a0536"
    keybytes :: ShortByteString
    keybytes = coerce @Bytes64
        $ "HiBoGpzDRAgrDmUXXTSnl7jCX6Hx5bzkU2jSxMbVI01yS+13" <>
          "EyOghnCidBXU0bH2gi2w9GhYGacpU6CrtwoFNg=="
    keychars :: LC.ByteString
    keychars = "HiBoGpzDRAgrDmUXXTSnl7jCX6Hx5bzkU2jSxMbVI01yS+13" <>
               "EyOghnCidBXU0bH2gi2w9GhYGacpU6CrtwoFNg=="

    sighex :: Bytes16
    sighex = "dd93289363854f0be4afd91bfd9ea5bd39789026606cda627c430a8745afb23c" <>
             "770aeac68fff8aa6c1d3f122f3db0a6efae39dfc128fa743babb860ae631104f"
    sigbytes :: ShortByteString
    sigbytes = coerce @Bytes64
        $ "3ZMok2OFTwvkr9kb/Z6lvTl4kCZgbNpifEMKh0Wvsjx3CurG" <>
          "j/+KpsHT8SLz2wpu+uOd/BKPp0O6u4YK5jEQTw=="
    sigchars :: LC.ByteString
    sigchars = "3ZMok2OFTwvkr9kb/Z6lvTl4kCZgbNpifEMKh0Wvsjx3CurG" <>
               "j/+KpsHT8SLz2wpu+uOd/BKPp0O6u4YK5jEQTw=="

    zmdhex :: Bytes16
    zmdhex =  "eda3998fa398b08b47fbde1f2c0c241d3efddafc31b3a776" <>
              "067d05fcef904643c36553dcf6102c5d0104f78dc0ed8e22"
    zmdbytes :: ShortByteString
    zmdbytes = coerce @Bytes16 zmdhex
    zmdchars :: LC.ByteString
    zmdchars = "eda3998fa398b08b47fbde1f2c0c241d3efddafc31b3a776" <>
               "067d05fcef904643c36553dcf6102c5d0104f78dc0ed8e22"

    tlsahex :: Bytes16
    tlsahex = "a0435521ac1be0ff6a734874bb489a1ce223a67a1049e7b927ddfd431fd850f5"
    tlsabytes :: ShortByteString
    tlsabytes = coerce @Bytes16 tlsahex
    tlsachars :: LC.ByteString
    tlsachars = "a0435521ac1be0ff6a734874bb489a1ce223a67a1049e7b927ddfd431fd850f5"

    sshkeybytes :: ShortByteString
    sshkeybytes  = coerce @Bytes16 "7d52bf15ec9445b5dba496d71f8ddf106b4b7265f4e166fb2c7d4b7831393d77"
    sshkeychars :: LC.ByteString
    sshkeychars  = "7d52bf15ec9445b5dba496d71f8ddf106b4b7265f4e166fb2c7d4b7831393d77"
    sshkeyhex   :: Bytes16
    sshkeyhex    = "7d52bf15ec9445b5dba496d71f8ddf106b4b7265f4e166fb2c7d4b7831393d77"

-----

testUtf8 :: TestTree
testUtf8 = testProperty "Text length matches Utf8 length" $
    forAllShow genText show $ \t ->
        LB.length (B.toLazyByteString (T.encodeUtf8Builder t)) ==
            fromIntegral (T.lengthWord8 t)

-----

testRData :: RRTYPE -> Gen RData -> TestTree
testRData ty gen = testProperty (presentString ty " codec round-trip") $
    forAllShow gen (flip presentString mempty) \ rd ->
        let rr = RR "boo.example.com" IN 0 rd
         in case encodeVerbatim $ putRR rr of
                 Left _    -> error "encoding didn't work"
                 Right enc -> case decodeAtWith 0 False (getRR baseCodecs Nothing) enc of
                     Left  err -> error $ show err ++ ": " ++ show @Bytes16 (coerce $ SB.toShort enc)
                     Right dec | dec == rr -> True
                               | otherwise -> error $ "got:\t" ++ presentString dec mempty

testCnEq :: RRTYPE -> Gen RData -> TestTree
testCnEq ty gen = testProperty (presentString ty " canonical equality") $
    forAllShow gen (flip presentString mempty) \ rd ->
        case rdataType rd of
            SIG   -> True
            RRSIG -> True
            RRTYPE t | (RData a) <- rd
                     , Right enc <- encodeCompressed $ cnEncode a
                     , len <- B.length enc
                     , Right dec <- decodeAtWith 0 False (getRData baseCodecs Nothing t len) enc
                         -> rd == dec
                     | otherwise -> False

-----

testCnOrd :: RRTYPE -> Gen RData -> TestTree
testCnOrd ty gen = testProperty (presentString ty " canonical order") $
    forAllShow gen2 (\ (r1, r2) -> presentString r1 ('\n' : presentString r2 mempty)) \ (rd1, rd2) ->
        case rdataType rd1 of
            SIG   -> True
            RRSIG -> True
            _ | Right enc1 <- encodeCompressed $ rdataEncodeCanonical rd1
              , Right enc2 <- encodeCompressed $ rdataEncodeCanonical rd2
                -> (rd1 `compare` rd2) == (enc1 `compare` enc2)
              | otherwise -> False
  where
    gen2 = (,) <$> gen <*> gen

-----

testOption :: OptNum -> Gen SomeOption -> TestTree
testOption onum gen = testProperty (presentString onum " EDNS option codec") $
    forAllShow gen (flip presentString mempty) \ opt ->
        case encodeVerbatim $ encode opt of
            Left _    -> error "encoding didn't work"
            Right buf ->
                case decodeAtWith 0 False (getMessage baseCodecs baseOptions) buf of
                     Left  err -> error $ show err
                     Right msg
                        | fmap ednsOptions (dnsMsgEx msg) == Just [opt] -> True
                        | otherwise -> False
  where
    encode opt = putRequest 0 mempty (Just edns) q
       where
         q = DnsTriple RootDomain SOA IN
         edns = EDNS 1 1400 [opt]

-----

genText :: Gen T.Text
genText = T.pack <$> listOf arbitrary

genA :: Gen RData
genA = RData . T_A <$> genIPv4

genNS, genMD, genMF, genCNAME, genMB, genMG, genMR :: Gen RData
genNS    = RData . T_NS <$> genDomain
genMD    = RData . T_MD <$> genDomain
genMF    = RData . T_MF <$> genDomain
genCNAME = RData . T_CNAME <$> genDomain
genMB    = RData . T_MB <$> genDomain
genMG    = RData . T_MG <$> genDomain
genMR    = RData . T_MR <$> genDomain

genSOA :: Gen RData
genSOA = RData <$.> T_SOA <$> genDomain
                          <*> genMbox
                          <*> arbitrary
                          <*> arbitrary
                          <*> arbitrary
                          <*> arbitrary
                          <*> arbitrary

genNULL :: Gen RData
genNULL = RData . T_NULL . coerce <$> genShortByteString

genWKS :: Gen RData
genWKS = do
    wksAddr4 <- genIPv4
    wksProto <- elements [UDP, TCP]
    wksPorts <- fromList <$> listOf arbitrary
    pure $ RData T_WKS{..}

genPTR :: Gen RData
genPTR = RData . T_PTR <$> genDomain

genHINFO :: Gen RData
genHINFO = RData <$.> T_HINFO <$> genCharString <*> genCharString

genMINFO :: Gen RData
genMINFO = RData <$.> T_MINFO <$> genDomain <*> genDomain

genMX :: Gen RData
genMX = RData <$.> T_MX <$> arbitrary <*> genDomain

genTXT :: Gen RData
genTXT = RData . T_TXT <$> genCharStrings
  where
    genCharStrings :: Gen (NonEmpty ShortByteString)
    genCharStrings = (:|) <$> genCharString <*> listOf genCharString

genRP :: Gen RData
genRP = RData <$.> T_RP <$> genDomain <*> genDomain

genAFSDB :: Gen RData
genAFSDB = RData <$.> T_AFSDB <$> arbitrary <*> genDomain

genX25 :: Gen RData
genX25 = RData . T_X25 <$> genDigits
  where
    -- Digit string of at least 4 bytes
    genDigits :: Gen ShortByteString
    genDigits = sized \n -> do
        k <- choose (4, min 255 n)
        SB.pack <$> vectorOf k (elements [0x30..0x39])

genISDN :: Gen RData
genISDN = do
    address <- genCharString
    ddi <- listToMaybe <$> do
        k <- choose (0,1)
        vectorOf k genCharString
    pure $ RData $ T_ISDN address ddi

genRT :: Gen RData
genRT = RData <$.> T_RT <$> arbitrary <*> genDomain

genNSAP :: Gen RData
genNSAP = RData . T_NSAP <$> genCharString

genNSAPPTR :: Gen RData
genNSAPPTR = RData . T_NSAPPTR <$> genDomain

genPX :: Gen RData
genPX = RData <$.> T_PX <$> arbitrary <*> genDomain <*> genDomain

genGPOS :: Gen RData
genGPOS = RData <$.> T_GPOS <$> genCharString <*> genCharString <*> genCharString

genAAAA :: Gen RData
genAAAA = RData . T_AAAA <$> genIPv6

genNXT :: Gen RData
genNXT = do
    nxtNext <- genDomain
    nxtBits <- toNxtTypes . (NXT :|) <$> listOf genRT7
    pure $ RData T_NXT{..}
  where
    genRT7 :: Gen RRTYPE
    genRT7 = RRTYPE <$> chooseBoundedIntegral (1,127)

genSRV :: Gen RData
genSRV = RData <$.> T_SRV <$> arbitrary
                          <*> arbitrary
                          <*> arbitrary
                          <*> genDomain

genNAPTR :: Gen RData
genNAPTR = RData <$.> T_NAPTR <$> arbitrary
                              <*> arbitrary
                              <*> genCharString
                              <*> genCharString
                              <*> genCharString
                              <*> genDomain

genKX :: Gen RData
genKX = RData <$.> T_KX <$> arbitrary <*> genDomain

genA6 :: Gen RData
genA6 = do
    a6 <- T_A6 <$> choose (0, 127) <*> genIPv6 <*> gend
    pure $ RData a6
  where
    gend = Just <$> genDomain

genDNAME :: Gen RData
genDNAME = RData . T_DNAME <$> genDomain

----

_genXDS :: forall (n :: Nat). Nat16 n => Gen (X_ds n)
_genXDS =
  X_DS <$> arbitrary
       <*> (coerce @Word8 <$> arbitrary)
       <*> (coerce @Word8 <$> arbitrary)
       <*> genShortByteString

genDS :: Gen RData
genDS = RData <$> (_genXDS :: Gen T_ds)

genCDS :: Gen RData
genCDS = RData <$> (_genXDS :: Gen T_cds)

genSSHFP :: Gen RData
genSSHFP = RData <$.> T_SSHFP <$> arbitrary
                              <*> arbitrary
                              <*> genShortByteString

_genXSIG :: forall (n :: Nat). Nat16 n => Gen (X_sig n)
_genXSIG =
  X_SIG <$> genRRTYPE
        <*> (coerce @Word8 <$> arbitrary)
        <*> arbitrary
        <*> arbitrary
        <*> (fromIntegral <$> arbitrary @Int32)
        <*> (fromIntegral <$> arbitrary @Int32)
        <*> arbitrary
        <*> genDomain
        <*> genShortByteString

genSIG :: Gen RData
genSIG = RData <$> (_genXSIG :: Gen T_sig)

genRRSIG :: Gen RData
genRRSIG = RData <$> (_genXSIG :: Gen T_rrsig)

_genXKEY :: forall (n :: Nat). Nat16 n => Gen (X_key n)
_genXKEY =
  X_KEY <$> arbitrary
        <*> arbitrary
        <*> (coerce @Word8 <$> arbitrary)
        <*> genShortByteString

genKEY :: Gen RData
genKEY = RData <$> (_genXKEY :: Gen T_key)

genDNSKEY :: Gen RData
genDNSKEY = RData <$> (_genXKEY :: Gen T_dnskey)

genCDNSKEY :: Gen RData
genCDNSKEY = RData <$> (_genXKEY :: Gen T_cdnskey)

genNSEC :: Gen RData
genNSEC = RData <$.> T_NSEC <$> genDomain <*> genNsecTypes

genNSEC3 :: Gen RData
genNSEC3 = RData <$.> T_NSEC3 <$> (coerce @Word8 <$> arbitrary)
                              <*> arbitrary
                              <*> arbitrary
                              <*> genCharString
                              <*> genCharString
                              <*> genNsecTypes

genNSEC3PARAM :: Gen RData
genNSEC3PARAM = RData <$.> T_NSEC3PARAM <$> (coerce @Word8 <$> arbitrary)
                                        <*> arbitrary
                                        <*> arbitrary
                                        <*> genCharString

genTLSA :: Gen RData
genTLSA = RData <$.> T_TLSA <$> arbitrary
                            <*> arbitrary
                            <*> arbitrary
                            <*> genShortByteString

genZONEMD :: Gen RData
genZONEMD = RData <$.> T_ZONEMD <$> arbitrary
                                <*> arbitrary
                                <*> arbitrary
                                <*> genDigest
  where
    genDigest :: Gen ShortByteString
    genDigest = sized \n -> do
        k <- choose (12, max 12 n)
        SB.pack <$> vectorOf k arbitrary

genSVCB :: Gen RData
genSVCB = RData <$.> T_SVCB <$> arbitrary <*> genDomain <*> genSVCParamValues

genHTTPS :: Gen RData
genHTTPS = RData <$.> T_HTTPS <$> arbitrary <*> genDomain <*> genSVCParamValues

genCAA :: Gen RData
genCAA = RData <$.> T_CAA <$> arbitrary <*> genTag <*> genShortByteString
  where
    genTag :: Gen ShortByteString
    genTag = sized \n -> do
        k <- choose (1, min 255 $ max 1 n)
        SB.pack <$> vectorOf k genld
    genld :: Gen Word8
    genld = elements $ filter isalnum [0..255]

genCSYNC :: Gen RData
genCSYNC = RData <$.> T_CSYNC <$> arbitrary <*> arbitrary <*> genNsecTypes

genOpaque :: Word16 -> Gen RData
genOpaque w = opaqueRData w <$> genShortByteString

----

genDAU, genDHU, genN3U :: Gen SomeOption
genDAU = SomeOption . O_DAU <$> listOf (coerce <$> arbitrary @Word8)
genDHU = SomeOption . O_DHU <$> listOf (coerce <$> arbitrary @Word8)
genN3U = SomeOption . O_N3U <$> listOf (coerce <$> arbitrary @Word8)

genECS :: Gen SomeOption
genECS = oneof [ SomeOption <$> genECSv4, SomeOption <$> genECSv6 ]
  where
    genECSv4 :: Gen O_ecs
    genECSv4 = do
        src <- genPL
        scp <- genPL
        ip  <- genIPv4
        let mip = maskIPv4 ip src
        return $ O_ECS src scp (IPv4 mip)
      where
        genPL = chooseBoundedIntegral (0, 32)
        maskIPv4 i n = masked i (intToMask $ fromIntegral n)
    genECSv6 :: Gen O_ecs
    genECSv6 = do
        src <- genPL
        scp <- genPL
        ip <- genIPv6
        let mip = maskIPv6 ip src
        return $ O_ECS src scp (IPv6 mip)
      where
        genPL = chooseBoundedIntegral (0, 128)
        maskIPv6 i n = masked i (intToMask $ fromIntegral n)

genNSID :: Gen SomeOption
genNSID = SomeOption . O_NSID <$> genShortByteString

genOpaqueOpt :: Gen SomeOption
genOpaqueOpt = opaqueOption <$> chooseBoundedIntegral (65001,65534)
                            <*> genShortByteString

-- low-level generators for parameter types

genSVCParamValues :: Gen SPVSet
genSVCParamValues = fromList <$> genList
  where
    genList = join $ sequence <$>
        sublistOf [ genMANDATORY
                  , genALPN
                  , genNDALPN
                  , genPORT
                  , genIPV4HINT
                  , genECH
                  , genIPV6HINT
                  , genDOHPATH
                  , genOpaqueSPV
                  ]

    genMANDATORY :: Gen SVCParamValue
    genMANDATORY =
        SVCParamValue . fromNonEmptyList @SPV_mandatory <$> genSVCParamKeys
      where
        genSVCParamKeys :: Gen (NonEmpty SVCParamKey)
        genSVCParamKeys = listOf' $ SVCParamKey <$> arbitrary

    genALPN :: Gen SVCParamValue
    genALPN = SVCParamValue . SPV_ALPN <$> listOf' genCharString

    genNDALPN :: Gen SVCParamValue
    genNDALPN = pure $ SVCParamValue SPV_NDALPN

    genPORT :: Gen SVCParamValue
    genPORT = SVCParamValue . SPV_PORT <$> arbitrary

    genIPV4HINT :: Gen SVCParamValue
    genIPV4HINT = SVCParamValue . SPV_IPV4HINT <$> listOf' genIPv4

    genIPV6HINT :: Gen SVCParamValue
    genIPV6HINT = SVCParamValue . SPV_IPV6HINT <$> listOf' genIPv6

    genECH :: Gen SVCParamValue
    genECH = SVCParamValue . SPV_ECH <$> (Bytes64 <$> genShortByteStringMinLen 4)

    genDOHPATH :: Gen SVCParamValue
    genDOHPATH = SVCParamValue . SPV_DOHPATH <$> genText

    genOpaqueSPV :: Gen SVCParamValue
    genOpaqueSPV = opaqueSPV <$> chooseBoundedIntegral (65280,65534) <*> genShortByteString

-- | Construct an explicit 'OpaqueSPV' service parameter key value pair from
-- the raw numeric key and short bytestring value.
opaqueSPV :: Word16 -> ShortByteString -> SVCParamValue
opaqueSPV (wordToNat16 -> SomeNat16 (_ :: proxy n)) bs =
    SVCParamValue $ (OpaqueSPV bs :: OpaqueSPV n)

uniqueOrdList :: (Ord a, Arbitrary a) => Gen [a]
uniqueOrdList = dedup <$> orderedList

dedup :: Ord a => [a] -> [a]
dedup [] = []
dedup (a:as) = a : go a as
  where
    go _ [] = []
    go x (y:ys)
      | x < y = y : go y ys
      | otherwise = go x ys

listOf' :: Gen a -> Gen (NonEmpty a)
listOf' g = nonEmpty g (listOf g)

nonEmpty :: Gen a -> Gen [a] -> Gen (NonEmpty a)
nonEmpty g gs = (:|) <$> g <*> gs

isalnum :: Word8 -> Bool
isalnum w = w - 0x30 < 10 || w .&. 0xdf - 0x41 < 26

genNsecTypes :: Gen NsecTypes
genNsecTypes = fromList <$> listOf genRRTYPE

genRRTYPE :: Gen RRTYPE
genRRTYPE = RRTYPE <$> arbitrary

genIPv4 :: Gen IPv4
genIPv4 = toIPv4w <$> arbitrary

genIPv6 :: Gen IPv6
genIPv6 = toIPv6w <$> arbitrary

genByteString :: Gen ByteString
genByteString = B.pack <$> listOf (arbitrary :: Gen Word8)

genShortByteString :: Gen ShortByteString
genShortByteString = SB.pack <$> listOf (arbitrary :: Gen Word8)

genByteStringMinLen :: Int -> Gen ByteString
genByteStringMinLen 0 = genByteString
genByteStringMinLen n = do
    mx <- max n <$> getSize
    l  <- chooseInt (n,mx)
    B.pack <$> vectorOf l (arbitrary @Word8)

genShortByteStringMinLen :: Int -> Gen ShortByteString
genShortByteStringMinLen 0 = genShortByteString
genShortByteStringMinLen n = do
    mx <- max n <$> getSize
    l  <- chooseInt (n,mx)
    SB.pack <$> vectorOf l (arbitrary @Word8)

-- | DNS /character-string/ of at most 255 bytes
genCharString :: Gen ShortByteString
genCharString = sized \n -> do
    k <- choose (0, min 255 n)
    SB.pack <$> vectorOf k arbitrary

genDomain :: Gen Domain
genDomain =
  elements [ $$(dnLit ".")
           , $$(dnLit "com")
           , $$(dnLit "example.org")
           , $$(dnLit "foo.example.com")
           , $$(dnLit "bar.example.com")
           , $$(dnLit "something.foo.example.com")
           ]

genMbox :: Gen Domain
genMbox =
  elements [ $$(mbLit "a@b")
           , $$(mbLit "first.last@example.com")
           , $$(mbLit "first.last@foo.example.com")
           , $$(mbLit "admin@com")
           ]
