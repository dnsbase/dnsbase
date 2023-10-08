{-# LANGUAGE
    ApplicativeDo
  , OverloadedLists
  , OverloadedStrings
  , RecordWildCards
  , TemplateHaskell
  #-}

import qualified Data.ByteString.Short as SB
import qualified Options.Applicative as O
import qualified System.IO as IO
import Data.ByteString.Short (ShortByteString)
import Data.Coerce (coerce)
import System.IO (stdout, BufferMode(..))

import Net.DNSBase

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

data Opts = Opts { opt_n :: !Int }

main :: IO ()
main = do
    Opts{..} <- getOpts
    IO.hSetBuffering stdout $ BlockBuffering $ Nothing
    IO.hSetBinaryMode stdout True
    loop opt_n
  where
    loop :: Int -> IO ()
    loop n
        | n > 0 = do
            mapM_ (hPutBuilder stdout) $ buildCompressed do
                putRR txt1
                putRR txt2
                putRR txt3
                putRR txt4
                putRR txt5
                putRR txt6
                putRR addr1
                putRR addr2
                putRR cname
                putRR dname
                putRR ptr
                putRR ds
                putRR cds
                putRR key
                putRR cky
                putRR sig
                putRR nsec
                putRR nsec3
                putRR nsec3p
                putRR ns
                putRR soa
                putRR opaque
                putRR mx
                putRR srv
                putRR afs
                putRR tlsa
            loop (n-1)
        | otherwise = pure ()

    getOpts :: IO Opts
    getOpts = O.execParser
        $  O.info (O.helper <*> optsParser)
        $  O.noIntersperse
        <> O.fullDesc
        <> O.header "main - exercise DNS library features"

    optsParser :: O.Parser Opts
    optsParser = do
        opt_n  <- O.argument O.auto
            ( O.metavar "iterations"
            <> O.showDefault
            <> O.value 1
            )
        pure Opts{..}
