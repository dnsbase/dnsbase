{-# LANGUAGE AllowAmbiguousTypes #-}
{-# OPTIONS_GHC -Wno-overlapping-patterns #-}
module Net.DNSBase.Decode.Map
    ( RDataMap
    , OptionMap
    , rdataMapEntry
    , baseCodecs
    , baseOptions
    ) where

import qualified Data.IntMap.Strict as IM
import Data.Void (Void, absurd)

import Net.DNSBase.Decode.Internal.Option
import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.EDNS.Internal.OptNum
import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.Util

import Net.DNSBase.EDNS.Option.ECS
import Net.DNSBase.EDNS.Option.NSID
import Net.DNSBase.EDNS.Option.Secalgs
import Net.DNSBase.Nat16

-- Builtin RData type modules
import Net.DNSBase.RData.A
import Net.DNSBase.RData.CAA
import Net.DNSBase.RData.Dnssec
import Net.DNSBase.RData.Obsolete
import Net.DNSBase.RData.SOA
import Net.DNSBase.RData.SRV
import Net.DNSBase.RData.SVCB
import Net.DNSBase.RData.SVCB.SPV
import Net.DNSBase.RData.SVCB.SVCParamKey
import Net.DNSBase.RData.SVCB.SVCParamValue
import Net.DNSBase.RData.TLSA
import Net.DNSBase.RData.TXT
import Net.DNSBase.RData.XNAME

-- | Placeholder for reserved RRTYPEs.
type Reserved :: Nat -> Type
data Reserved n = Reserved Void deriving (Typeable, Eq, Ord, Show)
instance (Nat16 n) => KnownRData (Reserved n) where
    rdType = RRTYPE $ natToWord16 @n
    rdTypePres = present @String "Reserved" . present (natToWord16 @n)
    rdEncode _   = failWith $ ReservedType (rdType @(Reserved n))
    rdDecode _ _ = failSGet $ "Reserved RDATA type: " ++ show (natToWord16 @n)
instance (Nat16 n) => Presentable (Reserved n) where
    present (Reserved v) = absurd v

rdataMapEntry :: forall a. KnownRData a => CodecOpts a -> (Int, SomeCodec)
rdataMapEntry (opts :: CodecOpts a) =
    (fromIntegral @Word16 . coerce $ rdType @a, SomeCodec (Proxy @a) opts)

-- | Default 'RDataMap' using all defined decoders
-- and reserving undecodable 'RRTYPE' values
baseCodecs :: RDataMap
baseCodecs = IM.fromList
    [ rdataMapEntry @(Reserved 0)      () -- 0 RFC6895
    , rdataMapEntry @T_a               () -- 1
    , rdataMapEntry @T_ns              () -- 2
    , rdataMapEntry @T_md              () -- 3
    , rdataMapEntry @T_mf              () -- 4
    , rdataMapEntry @T_cname           () -- 5
    , rdataMapEntry @T_soa             () -- 6
    , rdataMapEntry @T_mb              () -- 7
    , rdataMapEntry @T_mg              () -- 8
    , rdataMapEntry @T_mr              () -- 9
    , rdataMapEntry @T_null            () -- 10
    , rdataMapEntry @T_wks             () -- 11
    , rdataMapEntry @T_ptr             () -- 12
    , rdataMapEntry @T_hinfo           () -- 13
    , rdataMapEntry @T_minfo           () -- 14
    , rdataMapEntry @T_mx              () -- 15
    , rdataMapEntry @T_txt             () -- 16
    , rdataMapEntry @T_rp              () -- 17
    , rdataMapEntry @T_afsdb           () -- 18
    , rdataMapEntry @T_x25             () -- 19
    , rdataMapEntry @T_isdn            () -- 20
    , rdataMapEntry @T_rt              () -- 21
    , rdataMapEntry @T_nsap            () -- 22
    , rdataMapEntry @T_nsapptr         () -- 23
    , rdataMapEntry @T_sig             () -- 24
    , rdataMapEntry @T_key             () -- 25
    , rdataMapEntry @T_px              () -- 26
    , rdataMapEntry @T_gpos            () -- 27
    , rdataMapEntry @T_aaaa            () -- 28
                                          -- 29 LOC
    , rdataMapEntry @T_nxt             () -- 30
                                          -- 31 EID
                                          -- 32 NIMLOC
    , rdataMapEntry @T_srv             () -- 33
                                          -- 34 ATMA
    , rdataMapEntry @T_naptr           () -- 35
    , rdataMapEntry @T_kx              () -- 36
                                          -- 37 CERT
    , rdataMapEntry @T_a6              () -- 38
    , rdataMapEntry @T_dname           () -- 39
                                          -- 40 SINK
    , rdataMapEntry @(Reserved 41)     () -- OPT (hardwired)
                                          -- 42 APL
    , rdataMapEntry @T_ds              () -- 43
    , rdataMapEntry @T_sshfp           () -- 44
                                          -- 45 IPSECKEY
    , rdataMapEntry @T_rrsig           () -- 46
    , rdataMapEntry @T_nsec            () -- 47
    , rdataMapEntry @T_dnskey          () -- 48
                                          -- 49 DHCID
    , rdataMapEntry @T_nsec3           () -- 50
    , rdataMapEntry @T_nsec3param      () -- 51
    , rdataMapEntry @T_tlsa            () -- 52
                                          -- 53 SMIMEA
                                          -- 54 Unassigned
                                          -- 55 HIP
                                          -- 56 NINFO
                                          -- 57 RKEY
                                          -- 58 TALINK
    , rdataMapEntry @T_cds             () -- 59
    , rdataMapEntry @T_cdnskey         () -- 60
                                          -- 61 OPENPGPKEY
                                          -- 62 CSYNC
    , rdataMapEntry @T_zonemd          () -- 63
    , rdataMapEntry @T_svcb            baseSVCParams -- 64
    , rdataMapEntry @T_https           baseSVCParams -- 65
      ---- Special-use types
    , rdataMapEntry @(Reserved 128)    () -- NXNAME
    , rdataMapEntry @(Reserved 249)    () -- TKEY
    , rdataMapEntry @(Reserved 250)    () -- TSIG
    , rdataMapEntry @(Reserved 251)    () -- IXFR
    , rdataMapEntry @(Reserved 252)    () -- AXFR
      ---- Query-only types
    , rdataMapEntry @(Reserved 253)    () -- MAILB
    , rdataMapEntry @(Reserved 254)    () -- MAILA
    , rdataMapEntry @(Reserved 255)    () -- ANY
      ----
    , rdataMapEntry @T_caa             () -- 257
      ----
    , rdataMapEntry @(Reserved 65535)  () -- Reserved
    ]

-- | OPTCODE->decoder map for built-in EDNS options
-- Custom resolver configuration: TBD.
baseOptions :: OptionMap
baseOptions = IM.fromList
    [ (fromIntegral @Word16 $ coerce ECS,  optDecode @O_ecs)
    , (fromIntegral @Word16 $ coerce NSID, optDecode @O_nsid)
    , (fromIntegral @Word16 $ coerce DAU,  optDecode @O_dau)
    , (fromIntegral @Word16 $ coerce DHU,  optDecode @O_dhu)
    , (fromIntegral @Word16 $ coerce N3U,  optDecode @O_n3u)
    ]

spvMapEntry :: forall a. KnownSVCParamValue a
            => (Int, Int -> SGet SVCParamValue)
spvMapEntry =
    ( fromIntegral @Word16 . coerce $ spvKey @a
    , decodeSPV @a)

baseSVCParams :: SPVDecoderMap
baseSVCParams = IM.fromList
    [ spvMapEntry @SPV_mandatory
    , spvMapEntry @SPV_alpn
    , spvMapEntry @SPV_ndalpn
    , spvMapEntry @SPV_port
    , spvMapEntry @SPV_ipv4hint
    , spvMapEntry @SPV_ech
    , spvMapEntry @SPV_ipv6hint
    , spvMapEntry @SPV_dohpath
    ]
