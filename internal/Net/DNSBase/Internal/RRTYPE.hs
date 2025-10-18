{-# LANGUAGE ExplicitNamespaces #-}

module Net.DNSBase.Internal.RRTYPE
    ( -- * DNS RRTYPE numbers
      RRTYPE ( ..
             , A
             , NS
             , MD
             , MF
             , CNAME
             , SOA
             , MB
             , MG
             , MR
             , NULL
             , WKS
             , PTR
             , HINFO
             , MINFO
             , MX
             , TXT
             , RP
             , AFSDB
             , X25
             , ISDN
             , RT
             , NSAP
             , NSAPPTR
             , SIG
             , KEY
             , PX
             , GPOS
             , AAAA
             , LOC
             , NXT
             , EID
             , NIMLOC
             , SRV
             , ATMA
             , NAPTR
             , KX
             , CERT
             , A6
             , DNAME
             , SINK
             , OPT
             , APL
             , DS
             , SSHFP
             , IPSECKEY
             , RRSIG
             , NSEC
             , DNSKEY
             , NSEC3
             , NSEC3PARAM
             , TLSA
             , SMIMEA
             , CDS
             , CDNSKEY
             , OPENPGPKEY
             , CSYNC
             , ZONEMD
             , SVCB
             , HTTPS
             , DSYNC
             , NXNAME
             , IXFR
             , AXFR
             , MAILB
             , MAILA
             , ANY
             , CAA
             , AMTRELAY
             )
    -- ** Associated type-level naturals
    , type N_a
    , type N_ns
    , type N_md
    , type N_mf
    , type N_cname
    , type N_soa
    , type N_mb
    , type N_mg
    , type N_mr
    , type N_null
    , type N_wks
    , type N_ptr
    , type N_hinfo
    , type N_minfo
    , type N_mx
    , type N_txt
    , type N_rp
    , type N_afsdb
    , type N_x25
    , type N_isdn
    , type N_rt
    , type N_nsap
    , type N_nsapptr
    , type N_sig
    , type N_key
    , type N_px
    , type N_gpos
    , type N_aaaa
    , type N_loc
    , type N_nxt
    , type N_eid
    , type N_nimloc
    , type N_srv
    , type N_atma
    , type N_naptr
    , type N_kx
    , type N_cert
    , type N_a6
    , type N_dname
    , type N_sink
    , type N_opt
    , type N_apl
    , type N_ds
    , type N_sshfp
    , type N_ipseckey
    , type N_rrsig
    , type N_nsec
    , type N_dnskey
    , type N_nsec3
    , type N_nsec3param
    , type N_tlsa
    , type N_smimea
    , type N_cds
    , type N_cdnskey
    , type N_openpgpkey
    , type N_csync
    , type N_zonemd
    , type N_svcb
    , type N_https
    , type N_dsync
    , type N_nxname
    , type N_ixfr
    , type N_axfr
    , type N_mailb
    , type N_maila
    , type N_any
    , type N_caa
    , type N_amtrelay
    -- Internal
    , rrtypeMax
    ) where

import Net.DNSBase.Internal.Nat16
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

-- | DNS Resource Record type numbers.  The 'Presentable' instance displays the
-- standard presentation form of the type name for known types, or else
-- @TYPEnnnnn@ for a generic type number @nnnnn@.
--
newtype RRTYPE = RRTYPE Word16
    deriving newtype ( Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read )

instance Presentable RRTYPE where
    present A            = present @String "A"
    present NS           = present @String "NS"
    present MD           = present @String "MD"
    present MF           = present @String "MF"
    present CNAME        = present @String "CNAME"
    present SOA          = present @String "SOA"
    present MB           = present @String "MB"
    present MG           = present @String "MG"
    present MR           = present @String "MR"
    present NULL         = present @String "NULL"
    present WKS          = present @String "WKS"
    present PTR          = present @String "PTR"
    present HINFO        = present @String "HINFO"
    present MINFO        = present @String "MINFO"
    present MX           = present @String "MX"
    present TXT          = present @String "TXT"
    present RP           = present @String "RP"
    present AFSDB        = present @String "AFSDB"
    present X25          = present @String "X25"
    present ISDN         = present @String "ISDN"
    present RT           = present @String "RT"
    present NSAP         = present @String "NSAP"
    present NSAPPTR      = present @String "NSAP-PTR"
    present SIG          = present @String "SIG"
    present KEY          = present @String "KEY"
    present PX           = present @String "PX"
    present GPOS         = present @String "GPOS"
    present AAAA         = present @String "AAAA"
    present LOC          = present @String "LOC"
    present NXT          = present @String "NXT"
    present EID          = present @String "EID"
    present NIMLOC       = present @String "NIMLOC"
    present SRV          = present @String "SRV"
    present ATMA         = present @String "ATMA"
    present NAPTR        = present @String "NAPTR"
    present KX           = present @String "KX"
    present CERT         = present @String "CERT"
    present A6           = present @String "A6"
    present DNAME        = present @String "DNAME"
    present SINK         = present @String "SINK"
    present OPT          = present @String "OPT"
    present APL          = present @String "APL"
    present DS           = present @String "DS"
    present SSHFP        = present @String "SSHFP"
    present IPSECKEY     = present @String "IPSECKEY"
    present RRSIG        = present @String "RRSIG"
    present NSEC         = present @String "NSEC"
    present DNSKEY       = present @String "DNSKEY"
    present NSEC3        = present @String "NSEC3"
    present NSEC3PARAM   = present @String "NSEC3PARAM"
    present TLSA         = present @String "TLSA"
    present SMIMEA       = present @String "SMIMEA"
    present CDS          = present @String "CDS"
    present CDNSKEY      = present @String "CDNSKEY"
    present OPENPGPKEY   = present @String "OPENPGPKEY"
    present CSYNC        = present @String "CSYNC"
    present ZONEMD       = present @String "ZONEMD"
    present SVCB         = present @String "SVCB"
    present HTTPS        = present @String "HTTPS"
    present DSYNC        = present @String "DSYNC"
    present NXNAME       = present @String "NXNAME"
    present IXFR         = present @String "IXFR"
    present AXFR         = present @String "AXFR"
    present ANY          = present @String "ANY"
    present CAA          = present @String "CAA"
    present AMTRELAY     = present @String "AMTRELAY"
    present (RRTYPE ty)  = present @String "TYPE" . present ty

-- | [IP4 address](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern A           :: RRTYPE;      pattern A           = RRTYPE 1
type N_a            :: Nat;         type N_a                   = 1

-- | [Authoritative name server](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern NS          :: RRTYPE;      pattern NS          = RRTYPE 2
type N_ns           :: Nat;         type N_ns                  = 2

-- | [Mail destination (Obsolete - use MX)](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern MD          :: RRTYPE;      pattern MD          = RRTYPE 3
type N_md           :: Nat;         type N_md                  = 3

-- | [Mail forwarder (Obsolete - use MX)](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern MF          :: RRTYPE;      pattern MF          = RRTYPE 4
type N_mf           :: Nat;         type N_mf                  = 4

-- | [Canonical name for an alias](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern CNAME       :: RRTYPE;      pattern CNAME       = RRTYPE 5
type N_cname        :: Nat;         type N_cname               = 5

-- | [Start of a zone of authority](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern SOA         :: RRTYPE;      pattern SOA         = RRTYPE 6
type N_soa          :: Nat;         type N_soa                 = 6

-- | [Mailbox domain name (EXPERIMENTAL)](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern MB          :: RRTYPE;      pattern MB          = RRTYPE 7
type N_mb           :: Nat;         type N_mb                  = 7

-- | [Mail group member (EXPERIMENTAL)](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern MG          :: RRTYPE;      pattern MG          = RRTYPE 8
type N_mg           :: Nat;         type N_mg                  = 8

-- | [Mail rename domain name (EXPERIMENTAL)](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern MR          :: RRTYPE;      pattern MR          = RRTYPE 9
type N_mr           :: Nat;         type N_mr                  = 9

-- | [Null RR (EXPERIMENTAL)](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern NULL        :: RRTYPE;      pattern NULL        = RRTYPE 10
type N_null         :: Nat;         type N_null                = 10

-- | [Well known service description](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern WKS         :: RRTYPE;      pattern WKS         = RRTYPE 11
type N_wks          :: Nat;         type N_wks                 = 11

-- | [Domain name pointer](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern PTR         :: RRTYPE;      pattern PTR         = RRTYPE 12
type N_ptr          :: Nat;         type N_ptr                 = 12

-- | [Host information](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern HINFO       :: RRTYPE;      pattern HINFO       = RRTYPE 13
type N_hinfo        :: Nat;         type N_hinfo               = 13

-- | [mailbox information (EXPERIMENTAL)(https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern MINFO       :: RRTYPE;      pattern MINFO       = RRTYPE 14
type N_minfo        :: Nat;         type N_minfo               = 14

-- | [Mail exchange](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern MX          :: RRTYPE;      pattern MX          = RRTYPE 15
type N_mx           :: Nat;         type N_mx                  = 15

-- | [Text strings](https://tools.ietf.org/html/rfc1035#section-3.2.2).
pattern TXT         :: RRTYPE;      pattern TXT         = RRTYPE 16
type N_txt          :: Nat;         type N_txt                 = 16

-- | [Responsible Person](https://www.rfc-editor.org/rfc/rfc1183.html#section-2.2)
pattern RP          :: RRTYPE;      pattern RP          = RRTYPE 17
type N_rp           :: Nat;         type N_rp                  = 17

-- | [AFS Data Base location](https://tools.ietf.org/html/rfc1183#section-1),
pattern AFSDB       :: RRTYPE;      pattern AFSDB       = RRTYPE 18
type N_afsdb        :: Nat;         type N_afsdb               = 18

-- | [X.25 PSDN address](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.1).
pattern X25         :: RRTYPE;      pattern X25         = RRTYPE 19
type N_x25          :: Nat;         type N_x25                 = 19

-- | [ISDN address](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.2).
pattern ISDN        :: RRTYPE;      pattern ISDN        = RRTYPE 20
type N_isdn         :: Nat;         type N_isdn                = 20

-- | [Route Through](https://www.rfc-editor.org/rfc/rfc1183.html#section-3.3).
pattern RT          :: RRTYPE;      pattern RT          = RRTYPE 21
type N_rt           :: Nat;         type N_rt                  = 21

-- | [NSAP style address](https://www.rfc-editor.org/rfc/rfc1706.html#section-5).
-- [DEPRECATED](https://datatracker.ietf.org/doc/status-change-int-tlds-to-historic/)
pattern NSAP        :: RRTYPE;      pattern NSAP        = RRTYPE 22
type N_nsap         :: Nat;         type N_nsap                = 22

-- | [NSAP style PTR](https://www.rfc-editor.org/rfc/rfc1706.html#section-6).
-- [DEPRECATED](https://datatracker.ietf.org/doc/status-change-int-tlds-to-historic/)
pattern NSAPPTR     :: RRTYPE;      pattern NSAPPTR     = RRTYPE 23
type N_nsapptr      :: Nat;         type N_nsapptr             = 23

-- | [Security Signature](https://www.rfc-editor.org/rfc/rfc2535#section-4.1).
pattern SIG         :: RRTYPE;      pattern SIG         = RRTYPE 24
type N_sig          :: Nat;         type N_sig                 = 24

-- | [Security Key](https://www.rfc-editor.org/rfc/rfc2535#section-3.1).
pattern KEY         :: RRTYPE;      pattern KEY         = RRTYPE 25
type N_key          :: Nat;         type N_key                 = 25

-- | [X.400 mail mapping information](https://www.rfc-editor.org/rfc/rfc2163.html#section-4).
pattern PX          :: RRTYPE;      pattern PX          = RRTYPE 26
type N_px           :: Nat;         type N_px                  = 26

-- | [Geographical Position](https://www.rfc-editor.org/rfc/rfc1712.html#section-3).
pattern GPOS        :: RRTYPE;      pattern GPOS        = RRTYPE 27
type N_gpos         :: Nat;         type N_gpos                = 27

-- | [IP6 Address](https://tools.ietf.org/html/rfc3596#section-2.1).
pattern AAAA        :: RRTYPE;      pattern AAAA        = RRTYPE 28
type N_aaaa         :: Nat;         type N_aaaa                = 28

-- | [Location Information](https://www.rfc-editor.org/rfc/rfc1876.html#section-1).
-- Not implemented:
--
-- >   MSB                                           LSB
-- >   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  0|        VERSION        |         SIZE          |
-- >   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  2|       HORIZ PRE       |       VERT PRE        |
-- >   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  4|                   LATITUDE                    |
-- >   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  6|                   LATITUDE                    |
-- >   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  8|                   LONGITUDE                   |
-- >   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > 10|                   LONGITUDE                   |
-- >   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > 12|                   ALTITUDE                    |
-- >   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > 14|                   ALTITUDE                    |
-- >   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
pattern LOC         :: RRTYPE;      pattern LOC         = RRTYPE 29
type N_loc          :: Nat;         type N_loc                 = 29

-- | [Next Domain](https://www.rfc-editor.org/rfc/rfc2535.html#section-5.1).
pattern NXT         :: RRTYPE;      pattern NXT         = RRTYPE 30
type N_nxt          :: Nat;         type N_nxt                 = 30

-- | [Endpoint Identifier](http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt).
-- Not implemented.
--
-- >                                  1  1  1  1  1  1
-- >    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                       RDATA                   /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- *  RDATA: a string of octets containing the Endpoint Identifier.
--    The value is the binary encoding of the Identifier, meaningful
--    only to the system utilizing it.
--
pattern EID         :: RRTYPE;      pattern EID         = RRTYPE 31
type N_eid          :: Nat;         type N_eid                 = 31

-- | [Nimrod Locator](http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt).
-- Not impelemented
-- >                                  1  1  1  1  1  1
-- >    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                       RDATA                   /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- *  RDATA: a variable length string of octets containing the Nimrod
--    Locator.  The value is the binary encoding of the Locator
--    specified in the Nimrod protocol[[[ref to be supplied]]].
--
pattern NIMLOC      :: RRTYPE;      pattern NIMLOC      = RRTYPE 32
type N_nimloc       :: Nat;         type N_nimloc              = 32

-- | [Server Selection](https://datatracker.ietf.org/doc/html/rfc2782#page-9).
pattern SRV         :: RRTYPE;      pattern SRV         = RRTYPE 33
type N_srv          :: Nat;         type N_srv                 = 33

-- | [ATM Address](https://www.broadband-forum.org/download/af-dans-0152.000.pdf)
-- Not implemented.
--
-- >                                  1  1  1  1  1  1
-- >    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |          FORMAT       |                       |
-- > +--+--+--+--+--+--+--+--+                       |
-- > /                    ADDRESS                    /
-- > |                                               |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- * FORMAT: One octet that indicates the format of ADDRESS. The two possible
--   values for FORMAT are value 0 indicating ATM End System Address (AESA)
--   format and value 1 indicating E.164 format.
-- * ADDRESS: Variable length string of octets containing the ATM address of
--   the node to which this RR pertains.
--
pattern ATMA        :: RRTYPE;      pattern ATMA        = RRTYPE 34
type N_atma         :: Nat;         type N_atma                = 34

-- | [Naming Authority Pointer](https://www.rfc-editor.org/rfc/rfc3403.html#section-4)
pattern NAPTR       :: RRTYPE;      pattern NAPTR       = RRTYPE 35
type N_naptr        :: Nat;         type N_naptr               = 35

-- | [Key Exchanger](https://www.rfc-editor.org/rfc/rfc2230.html#section-2)
pattern KX          :: RRTYPE;      pattern KX          = RRTYPE 36
type N_kx           :: Nat;         type N_kx                  = 36

-- | [Cerificate](https://www.rfc-editor.org/rfc/rfc4398.html#section-2)
-- Not implemented.
--
-- >                     1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- > 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |             type              |             key tag           |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |   algorithm   |                                               /
-- > +---------------+            certificate or CRL                 /
-- > /                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
--
pattern CERT        :: RRTYPE;      pattern CERT        = RRTYPE 37
type N_cert         :: Nat;         type N_cert                = 37

-- | [A6](https://www.rfc-editor.org/rfc/rfc2874.html#section-3.1).
pattern A6          :: RRTYPE;      pattern A6          = RRTYPE 38
type N_a6           :: Nat;         type N_a6                  = 38

-- | [Name redirection](https://tools.ietf.org/html/rfc6672#section-2.1).
pattern DNAME       :: RRTYPE;      pattern DNAME       = RRTYPE 39
type N_dname        :: Nat;         type N_dname               = 39

-- | [SINK](https://datatracker.ietf.org/doc/html/draft-eastlake-kitchen-sink-02#section-2).
-- Not implemented.
--
-- >                                 1  1  1  1  1  1
-- >   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |         coding        |       subcoding       |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                                               /
-- > /                     data                      /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
pattern SINK        :: RRTYPE;      pattern SINK        = RRTYPE 40
type N_sink         :: Nat;         type N_sink                = 40

-- | [DNS extension options](https://tools.ietf.org/html/rfc6891#section-6.1).
pattern OPT         :: RRTYPE;      pattern OPT         = RRTYPE 41
type N_opt          :: Nat;         type N_opt                 = 41

-- | [Address prefix list](https://datatracker.ietf.org/doc/html/rfc3123#section-10).
-- Not implemented.  Zero or more items of
-- [the form](https://datatracker.ietf.org/doc/html/rfc3123#section-4):
--
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- > |                          ADDRESSFAMILY                        |
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- > |             PREFIX            | N |         AFDLENGTH         |
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- > /                            AFDPART                            /
-- > |                                                               |
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
--
-- - Family 1 is IPv4, Family 2 is IPv6.
-- - The AFDPART is stripped of all trailing zero octets, even if the
--   result ends up with fewer bits than the prefix.
--
pattern APL         :: RRTYPE;      pattern APL         = RRTYPE 42
type N_apl          :: Nat;         type N_apl                 = 42

-- | [Delegation Signer](https://www.rfc-editor.org/rfc/rfc3658#section-5)
-- See [RFC4034](https://www.rfc-editor.org/rfc/rfc4034.html#section-5) for
-- protocol details.
pattern DS          :: RRTYPE;      pattern DS          = RRTYPE 43
type N_ds           :: Nat;         type N_ds                  = 43

-- | [SSH Key fingerprint](https://www.rfc-editor.org/rfc/rfc4255.html#section-5).
pattern SSHFP       :: RRTYPE;      pattern SSHFP       = RRTYPE 44
type N_sshfp        :: Nat;         type N_sshfp               = 44

-- | [IPSEC KEY](https://www.rfc-editor.org/rfc/rfc4255.html#section-5).
pattern IPSECKEY    :: RRTYPE;      pattern IPSECKEY    = RRTYPE 45
type N_ipseckey     :: Nat;         type N_ipseckey            = 45

-- | [RRSIG](https://www.rfc-editor.org/rfc/rfc3755#section-4.1)
-- See [RFC4034](https://www.rfc-editor.org/rfc/rfc4034.html#section-3)
-- for protocol details.
pattern RRSIG       :: RRTYPE;      pattern RRSIG       = RRTYPE 46
type N_rrsig        :: Nat;         type N_rrsig               = 46

-- | [NSEC](https://www.rfc-editor.org/rfc/rfc3755#section-4.1)
-- See [RFC4034](https://www.rfc-editor.org/rfc/rfc4034.html#section-4)
-- for protocol details.
pattern NSEC        :: RRTYPE;      pattern NSEC        = RRTYPE 47
type N_nsec         :: Nat;         type N_nsec                = 47

-- | [DNSKEY](https://www.rfc-editor.org/rfc/rfc3755#section-4.1)
-- See [RFC4034](https://www.rfc-editor.org/rfc/rfc4034.html#section-2)
-- for protocol details.
pattern DNSKEY      :: RRTYPE;      pattern DNSKEY      = RRTYPE 48
type N_dnskey       :: Nat;         type N_dnskey              = 48

-- | [Hashed authenticated denial of existence](https://www.rfc-editor.org/rfc/rfc5155.html#section-11)
pattern NSEC3       :: RRTYPE;      pattern NSEC3       = RRTYPE 50
type N_nsec3        :: Nat;         type N_nsec3               = 50

-- | [NSEC3PARAM](https://www.rfc-editor.org/rfc/rfc5155.html#section-4).
pattern NSEC3PARAM  :: RRTYPE;      pattern NSEC3PARAM  = RRTYPE 51
type N_nsec3param   :: Nat;         type N_nsec3param          = 51

-- | [DANE TLSA](https://www.rfc-editor.org/rfc/rfc6698.html#section-7).
pattern TLSA        :: RRTYPE;      pattern TLSA        = RRTYPE 52
type N_tlsa         :: Nat;         type N_tlsa                = 52

-- | [DANE SMIMEA](https://www.rfc-editor.org/rfc/rfc8162.html#section-8).
pattern SMIMEA      :: RRTYPE;      pattern SMIMEA      = RRTYPE 53
type N_smimea       :: Nat;         type N_smimea              = 53

-- | [Child DS](https://www.rfc-editor.org/rfc/rfc7344.html#section-7).
-- The CDS RRset expresses what the Child would like the DS RRset to look like.
pattern CDS         :: RRTYPE;      pattern CDS         = RRTYPE 59
type N_cds          :: Nat;         type N_cds                 = 59

-- | [Child DNSKEY](https://www.rfc-editor.org/rfc/rfc7344.html#section-7).
-- DNSKEY(s) the Child wants reflected in DS.
pattern CDNSKEY     :: RRTYPE;      pattern CDNSKEY     = RRTYPE 60
type N_cdnskey      :: Nat;         type N_cdnskey             = 60

-- | [OPENPGP Key](https://www.rfc-editor.org/rfc/rfc7929.html#section-8.1).
pattern OPENPGPKEY  :: RRTYPE;      pattern OPENPGPKEY  = RRTYPE 61
type N_openpgpkey   :: Nat;         type N_openpgpkey          = 61

-- | [Child-To-Parent Synchronization](https://www.rfc-editor.org/rfc/rfc7477.html#section-6)
pattern CSYNC       :: RRTYPE;      pattern CSYNC       = RRTYPE 62
type N_csync        :: Nat;         type N_csync               = 62

-- | [Zone Message Digest](https://www.rfc-editor.org/rfc/rfc8976.html#section-5.1)
pattern ZONEMD      :: RRTYPE;      pattern ZONEMD      = RRTYPE 63
type N_zonemd       :: Nat;         type N_zonemd              = 63

-- | [General Purpose Service Binding](https://www.rfc-editor.org/rfc/rfc9460.html#name-svcb-rr-type)
pattern SVCB        :: RRTYPE;      pattern SVCB        = RRTYPE 64
type N_svcb         :: Nat;         type N_svcb                = 64

-- | [SVCB-compatible type for use with HTTP](https://www.rfc-editor.org/rfc/rfc9460.html#name-https-rr-type)
pattern HTTPS       :: RRTYPE;      pattern HTTPS       = RRTYPE 65
type N_https        :: Nat;         type N_https               = 65

-- | [Generalized DNS Notifications](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-generalized-notify-09#name-dsync-rr-type)
pattern DSYNC       :: RRTYPE;      pattern DSYNC       = RRTYPE 66
type N_dsync        :: Nat;         type N_dsync               = 66

-- | [NXDOMAIN indicator for Compact Denial of Existence](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-compact-denial-of-existence-04#section-3.4)
pattern NXNAME      :: RRTYPE;      pattern NXNAME      = RRTYPE 128
type N_nxname       :: Nat;         type N_nxname              = 128

-- | Incremental transfer (RFC1995)
pattern IXFR        :: RRTYPE;      pattern IXFR        = RRTYPE 251
type N_ixfr         :: Nat;         type N_ixfr                = 251

-- | Zone transfer (RFC5936)
pattern AXFR        :: RRTYPE;      pattern AXFR        = RRTYPE 252
type N_axfr         :: Nat;         type N_axfr                = 252

-- | [A request for mailbox-related records (MB, MG or MR)](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.3)
pattern MAILB       :: RRTYPE;      pattern MAILB       = RRTYPE 253
type N_mailb        :: Nat;         type N_mailb               = 253

-- | [A request for mail agent RRs (Obsolete - see MX)](https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.3)
pattern MAILA       :: RRTYPE;      pattern MAILA       = RRTYPE 254
type N_maila        :: Nat;         type N_maila               = 254

-- | A request for all records the server/cache has available
pattern ANY         :: RRTYPE;      pattern ANY         = RRTYPE 255
type N_any          :: Nat;         type N_any                 = 255

-- | Certification Authority Authorization (RFC6844)
pattern CAA         :: RRTYPE;      pattern CAA         = RRTYPE 257
type N_caa          :: Nat;         type N_caa                 = 257

-- | Automatic Multicast Tunneling Relay (RFC8777)
pattern AMTRELAY    :: RRTYPE;      pattern AMTRELAY    = RRTYPE 260
type N_amtrelay     :: Nat;         type N_amtrelay            = 260

rrtypeMax :: RRTYPE
rrtypeMax = AMTRELAY
{-# INLINE rrtypeMax #-}
