{-# LANGUAGE
    ApplicativeDo
  , RecordWildCards
  , OverloadedStrings
  , OverloadedLists
  , TemplateHaskell
  #-}

module Main where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Short as SB
import qualified Options.Applicative as O
import Data.Coerce (coerce)
import Data.ByteString.Short (ShortByteString)
import Data.ByteString.Base32.Hex (encodeBase32Unpadded')
import Data.IP (toIPv4, toIPv6)
import System.IO (stdout, BufferMode(..), hSetBuffering, hSetBinaryMode)

import Net.DNSBase

exdom :: Domain
exdom = $$(dnLit "example.org")
mkRD :: KnownRData a => a -> RR
mkRD = RR exdom IN 300 . RData

ip4 :: Int -> IPv4
ip4 n =
    let a1 = n `mod` 16
        a2 = n `mod` 8
        a3 = n `mod` 4
        a4 = n `mod` 2
     in toIPv4 [a1,a2,a3,a4]

ip6 :: Int -> IPv6
ip6 n =
    let a1 = n `mod` 16
        a2 = n `mod` 8
        a3 = n `mod` 4
        a4 = n `mod` 2
     in toIPv6 [0x2001, 0, a4, 0x167, 0, a3, a2, a1]

hash :: ShortByteString
hash = coerce @Bytes16 "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

key, sig :: ShortByteString
sig = coerce @Bytes64 "EIJK5j86gvtYU90Cb3jbIa+xH8lntJoG8bgG6dkgCu/VY2XenqCi8VHUfq0tjW2hlQmfbYj3c6V9T0g0RQlFH1hHeH/J4gxqzyJZU+EsxxD9fzOYjuHmEmJBE15QD/YQ8mU5K64SVOYs7F+BcFcduwyKWIPkwwOSKK0Y04/mhTvHn9HAjD0J0vfPTDfZs748IKOOvH7RAp5ryAImSn8S4g6wQaFdxgHhzNUT0TNbDFrTBYDheFHbJcNS+8Yy+9pBqwshb3aDjWzQ9i1JoSfXXWNu4n1j6jGOOcflhYBU10NcZn+VDz6tsKqrt3JlTtIjHUVgp3pQhLpJGA5RbJ+IrA=="
key = "4xQugTVSY2+Xu6J390EnCLmGKAtoR+7h5J9kJa0H/N5W4p8P43aSX4y67OqH4wiW/QD4tKrv0YbdeO6ynhKoTQ=="

nsec3owner :: Domain
nsec3owner = $$(dnLit $ BS.unpack $ encodeBase32Unpadded' (B.pack [0..19]) <> ".example.com")

nsec3next :: ShortByteString
nsec3next = SB.pack [1..20]

emptysha2 :: ShortByteString
emptysha2 = coerce @Bytes16 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

soa, rrsig, afs, hi, txt, ptr, nsec, nsec3, nsec3param :: RR
soa = mkRD $ T_SOA { soaMname = $$(dnLit "nsa.example.com")
                   , soaRname = $$(mbLit "postmaster@example.com")
                   , soaSerial = 1
                   , soaRefresh = 3600      -- 1H
                   , soaRetry   = 300       -- 5m
                   , soaExpire  = 7 * 86400 -- 7d
                   , soaMinttl = 300
                   }
rrsig = mkRD $ T_RRSIG SOA 8 1 172800 1582491183 1581333041 40264 exdom sig
afs = mkRD $ T_AFSDB 1 $$(dnLit "afsdb.example.org")
hi = mkRD $ T_HINFO "alpha" "NetBSD 8"
txt = mkRD $ T_TXT $ "v=spf1" :| [" include:_spf.example.com", " ~all"]
ptr = mkRD $ T_PTR $$(dnLit "www.example.org")
nsec = mkRD $ T_NSEC $$(dnLit "www.example.org")
              [SOA, DNSKEY, NS, RRSIG, MX, NSEC, TXT]
nsec3 = RR nsec3owner IN 300 $ RData
    $ T_NSEC3 N3_SHA1 0 0 "feedcafe" nsec3next
      [SOA, DNSKEY, NS, RRSIG, MX, NSEC, TXT]
nsec3param = mkRD $ T_NSEC3PARAM N3_SHA1 1 0 "feedcafe"

data Opts = Opts
    { opt_n   :: !Int
    }

main :: IO ()
main = do
    Opts{..} <- getOpts
    hSetBuffering stdout $ BlockBuffering $ Nothing
    hSetBinaryMode stdout True
    hPutBuilder stdout $ loop opt_n mempty
  where
    loop n
        | n > 0 =
          presentLn (mkRD $ T_DS 12345 13 2 hash)
          . presentLn (mkRD $ T_CDS 0 0 0 "\0")
          . presentLn (mkRD $ T_DNSKEY 256 3 13 key)
          . presentLn (mkRD $ T_CDNSKEY 0 3 0 "\0")
          . presentLn soa
          . presentLn rrsig
          . presentLn (mkRD $ T_NS $$(dnLit "nsa.example.org."))
          . presentLn (mkRD $ T_CNAME $$(dnLit "www.example.org."))
          . presentLn (mkRD $ T_DNAME $$(dnLit "example.net."))
          . presentLn (mkRD $ T_MX 10 $$(dnLit "smtp.example.org."))
          . presentLn (mkRD $ T_SRV 100 0 389 $$(dnLit "ldap.example.org."))
          . presentLn afs
          . presentLn hi
          . presentLn txt
          . presentLn (mkRD $! T_A $! ip4 n)
          . presentLn (mkRD $! T_AAAA $! ip6 n)
          . presentLn ptr
          . presentLn nsec
          . presentLn nsec3
          . presentLn nsec3param
          . presentLn (RR $$(dnLit "_25._tcp.mx1.example.com")
                          IN 300 $ RData $ T_TLSA 3 1 1 emptysha2)
          . presentLn (mkRD $ T_NULL (coerce @Bytes16 "DEADBEEF"))
          . presentLn (RR exdom IN 300 $ opaqueRData 12345 (coerce @Bytes16 "c0000201"))
          . loop (n-1)
        | otherwise = id

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
