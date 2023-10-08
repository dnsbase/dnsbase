{-# LANGUAGE
    OverloadedLists
  , OverloadedStrings
  , RecordWildCards
  , TemplateHaskell
  #-}
module Main (main) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Short as SB
import Data.ByteString.Short (ShortByteString)
import Data.Coerce (coerce)
import Data.Either (fromRight)
import Data.Word (Word8)

import Net.DNSBase

import Test.Tasty.Bench

main :: IO ()
main = defaultMain
    [ bench "towire"       $ whnf parseDomain pdom
    , bench "fromwire"     $ whnf presentStrict ldom
    , bench "enc question" $ whnf encodeQuestion question
    , bench "enc answer"   $ whnf encodeAnswer answer
    , bench "compress"     $ whnf encodeDomains dlist
    ]
  where
    bs = B.pack $ map i2w [17..36]
    i2w :: Int -> Word8
    i2w i = fromIntegral $ i*i

    pdom = "12345.example.com"
    ldom = $$(dnLit "12345.example.com")

    question = Question $$(dnLit "example.com") MX IN
    encodeQuestion = fromRight B.empty . enc
      where
        enc :: Question -> Either (EncodeErr (Maybe RData)) B.ByteString
        enc q = encodeVerbatim $ putRequest 0xbeef (RDflag <> ADflag) (Just defaultEDNS) q

    zone = $$(dnLit "example.com")

    hash :: ShortByteString
    hash = coerce @Bytes16 "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
    pkey, psig :: ShortByteString
    pkey = coerce @Bytes64 "4xQugTVSY2+Xu6J390EnCLmGKAtoR+7h5J9kJa0H/N5W4p8P43aSX4y67OqH4wiW/QD4tKrv0YbdeO6ynhKoTQ=="
    psig = coerce @Bytes64 "EIJK5j86gvtYU90Cb3jbIa+xH8lntJoG8bgG6dkgCu/VY2XenqCi8VHUfq0tjW2hlQmfbYj3c6V9T0g0RQlFH1hHeH/J4gxqzyJZU+EsxxD9fzOYjuHmEmJBE15QD/YQ8mU5K64SVOYs7F+BcFcduwyKWIPkwwOSKK0Y04/mhTvHn9HAjD0J0vfPTDfZs748IKOOvH7RAp5ryAImSn8S4g6wQaFdxgHhzNUT0TNbDFrTBYDheFHbJcNS+8Yy+9pBqwshb3aDjWzQ9i1JoSfXXWNu4n1j6jGOOcflhYBU10NcZn+VDz6tsKqrt3JlTtIjHUVgp3pQhLpJGA5RbJ+IrA=="

    fakesha12 :: ShortByteString
    fakesha12 = SB.pack [1..20]

    mkRD :: KnownRData a => Domain -> a -> RR
    mkRD d a = RR d IN 300 $ RData a

    txt1, txt2, txt3, txt4, txt5, txt6 :: RR;
    txt1 = mkRD $$(dnLit "example.nl") $ T_TXT
                $ "offset" :| [" 0"]
    txt2 = mkRD $$(dnLit "example.nl") $ T_TXT
                $ "pointer to offset 0" :| []
    txt3 = mkRD $$(dnLit "www.example.nl") $ T_TXT
                $ "www -> offset 0" :| []
    txt4 = mkRD $$(dnLit "example.dk") $ T_TXT
                $ "new ccTLD" :| []
    txt5 = mkRD $$(dnLit "example.dk") $ T_TXT
                $ "pointer to dk ccTLD" :| []
    txt6 = mkRD $$(dnLit "www.example.dk") $ T_TXT
                $ "www -> dk ccTLD" :| []

    addr1, addr2 :: RR
    addr1 = mkRD $$(dnLit "addr1.example.se") $ T_A "192.0.2.1"
    addr2 = mkRD $$(dnLit "www.example.se")   $ T_AAAA "2001:db8::dead:beef"

    cname, dname, ptr :: RR
    cname = mkRD $$(dnLit "cname.example.se")
        $ T_CNAME $$(dnLit "cname.example")
    dname = mkRD $$(dnLit "_tcp.a.example.se")
        $ T_DNAME $$(dnLit "_tlsa.name")
    ptr   = mkRD $$(dnLit "10.in-addr.arpa")
        $ T_PTR $$(dnLit "ptr")

    ds, cds, key, cky, sig :: RR
    ds  = mkRD $$(dnLit "ds.example.dk")
        $ T_DS  12345 13 2 hash
    cds = mkRD $$(dnLit "cds.example.dk")
        $ T_CDS 12345 13 2 hash
    key = mkRD $$(dnLit "dnskey.example.se")
        $ T_DNSKEY  256 3 13 pkey
    cky = mkRD $$(dnLit "cdnskey.example.se")
        $ T_CDNSKEY 256 3 13 pkey
    sig = mkRD $$(dnLit "rrsig.example.nl")
        $ T_RRSIG SOA 8 1 172800 1582491183 1581333041 40264 $$(dnLit "example.nl") psig

    nsec, nsec3, nsec3p :: RR
    nsec = mkRD $$(dnLit "nsec.example.dk")
        $ T_NSEC $$(dnLit "example.dk")
          [SOA, DNSKEY, NS, RRSIG, MX, NSEC, TXT]
    nsec3 = mkRD $$(dnLit "nsec3.example.dk")
        $ T_NSEC3 N3_SHA1 0 0 "" fakesha12
          [SOA, DNSKEY, NS, RRSIG, MX, NSEC, TXT]
    nsec3p = mkRD $$(dnLit "nsec3param.example.dk")
        $ T_NSEC3PARAM N3_SHA1 1 0 ""

    ns, soa :: RR
    ns  = mkRD $$(dnLit "example.nl")
        $ T_NS $$(dnLit "ns1.example.nl")
    soa = mkRD $$(dnLit "example.nl") $ T_SOA
               $$(dnLit "ns1.example.nl")
               $$(mbLit "hostmaster@example.nl") 1 3600 300 (7 * 86400) 300

    opaque :: RR
    opaque = RR $$(dnLit "whatami.example") IN 300
        $ opaqueRData 1 "c0000201"

    mx, srv, afs :: RR
    mx  = mkRD $$(dnLit "ietf.org")
        $ T_MX 10 $$(dnLit "mail.ietf.org")
    srv = mkRD $$(dnLit "ietf.org")
        $ T_SRV 100 0 389 $$(dnLit "ldap.ietf.org")
    afs = mkRD $$(dnLit "athena.mit.edu")
        $ T_AFSDB 1 $$(dnLit "afsdb.athena.mit.edu")

    tlsa :: RR
    tlsa = mkRD $$(dnLit "_25._tcp.mail.ietf.org")
        $ T_TLSA 3 1 1 hash

    answer = mkAnswer zone MX NOERROR (RDflag <> RAflag <> ADflag) (Just defaultEDNS)
        [ txt1, txt2, txt3, txt4, txt5, txt6
        , addr1, addr2, cname, ptr, ns, dname
        , ds, cds, key, cky, sig, nsec, nsec3, nsec3p
        , soa, opaque, mx, srv, afs, tlsa ]

    mkAnswer qname qtype rc fl edns an = DNSMessage{..}
      where
        dnsMsgId = 0xbeef
        dnsMsgOp = Query
        dnsMsgRC = rc
        dnsMsgFl = fl
        dnsMsgEx = edns
        dnsMsgQu = [Question qname qtype IN]
        dnsMsgAn = an
        dnsMsgNs = []
        dnsMsgAr = []

    encodeAnswer :: DNSMessage -> B.ByteString
    encodeAnswer   = fromRight B.empty . enc
      where
        enc :: DNSMessage -> Either (EncodeErr (Maybe RData)) B.ByteString
        enc msg = encodeCompressed $ putMessage msg

    dlist = [zone, zone, mx1, zone, mx2, mx1, mx2]
      where
        mx1 = $$(dnLit "mx1.example.com")
        mx2 = $$(dnLit "mx2.example.com")

    encodeDomains :: [Domain] -> B.ByteString
    encodeDomains = fromRight B.empty . enc
      where
        enc :: [Domain] -> Either (EncodeErr (Maybe ())) B.ByteString
        enc doms = encodeCompressed $ mapM_ putDomain doms
