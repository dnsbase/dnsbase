{-|
Module      : Net.DNSBase.RData.SVCB.SVCParamKey
Description : SVCB / HTTPS service-parameter key codes
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 16-bit numeric keys that select among service-parameter
values inside an @SVCB@ or @HTTPS@ resource record.  The keys
that were initially registered are listed in
[RFC 9460 section 14.3.2](https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2),
with subsequent additions tracked in the
[SvcParamKey IANA registry](https://www.iana.org/assignments/dns-svcb/dns-svcb.xhtml).
The bidirectional patterns below cover the keys that have
standardised value formats in this library; unknown keys are
carried as 'Net.DNSBase.RData.SVCB.OpaqueSPV' values.
-}

module Net.DNSBase.RData.SVCB.SVCParamKey where

import Data.Word (Word16)

import Net.DNSBase.Present


-- | A service-parameter key code
-- ([RFC 9460 section 2.1](https://datatracker.ietf.org/doc/html/rfc9460#section-2.1)).
-- The pattern synonyms below name the keys that have standardised
-- value formats; an unrecognised code keeps its numeric form and
-- presents as @keyN@.
newtype SVCParamKey = SVCParamKey Word16
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

-- | Keys the client must understand to use this RR
-- [RFC9460, Section 14.3.2](https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2)
pattern MANDATORY     :: SVCParamKey ; pattern MANDATORY     = SVCParamKey 0

-- | Application-Layer Protocol Negotiation identifiers
-- [RFC9460, Section 14.3.2](https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2)
pattern ALPN          :: SVCParamKey ; pattern ALPN          = SVCParamKey 1

-- | Suppress the default ALPN for this scheme
-- [RFC9460, Section 14.3.2](https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2)
pattern NODEFAULTALPN :: SVCParamKey ; pattern NODEFAULTALPN = SVCParamKey 2

-- | Alternative TCP/UDP port
-- [RFC9460, Section 14.3.2](https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2)
pattern PORT          :: SVCParamKey ; pattern PORT          = SVCParamKey 3

-- | Speculative IPv4 address hints
-- [RFC9460, Section 14.3.2](https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2)
pattern IPV4HINT      :: SVCParamKey ; pattern IPV4HINT      = SVCParamKey 4

-- | Encrypted Client Hello configuration
-- [RFC9848, IANA Considerations](https://datatracker.ietf.org/doc/html/rfc9848#name-iana-considerations)
pattern ECH           :: SVCParamKey ; pattern ECH           = SVCParamKey 5

-- | Speculative IPv6 address hints
-- [RFC9460, Section 14.3.2](https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2)
pattern IPV6HINT      :: SVCParamKey ; pattern IPV6HINT      = SVCParamKey 6

-- | URI template for DNS-over-HTTPS resolver discovery
-- [RFC9461, Section 4](https://datatracker.ietf.org/doc/html/rfc9461#section-4)
pattern DOHPATH       :: SVCParamKey ; pattern DOHPATH       = SVCParamKey 7

-- | Oblivious HTTP support indicator
-- [RFC9540, Section 4](https://datatracker.ietf.org/doc/html/rfc9540#section-4)
pattern OHTTP         :: SVCParamKey ; pattern OHTTP         = SVCParamKey 8

-- | TLS supported groups
-- [draft-ietf-tls-key-share-prediction-04, section 5](https://datatracker.ietf.org/doc/html/draft-ietf-tls-key-share-prediction-04#section-5)
pattern TLSGROUPS     :: SVCParamKey ; pattern TLSGROUPS     = SVCParamKey 9

-- | DNS over CoAP path [RFC9953, Section 3](https://datatracker.ietf.org/doc/html/rfc9953#section-8.2)
pattern DOCPATH       :: SVCParamKey ; pattern DOCPATH       = SVCParamKey 10

-- | Provisioning Domain [RFC-ietf-intarea-proxy-config-14, Section 7.5](https://datatracker.ietf.org/doc/html/draft-ietf-intarea-proxy-config-14#section-7.5)
pattern PVD           :: SVCParamKey ; pattern PVD           = SVCParamKey 11

instance Presentable SVCParamKey where
    present MANDATORY       = present @String "mandatory"
    present ALPN            = present @String "alpn"
    present NODEFAULTALPN   = present @String "no-default-alpn"
    present PORT            = present @String "port"
    present IPV4HINT        = present @String "ipv4hint"
    present ECH             = present @String "ech"
    present IPV6HINT        = present @String "ipv6hint"
    present DOHPATH         = present @String "dohpath"
    present OHTTP           = present @String "ohttp"
    present TLSGROUPS       = present @String "tls-supported-groups"
    present DOCPATH         = present @String "docpath"
    present PVD             = present @String "pvd"
    present (SVCParamKey n) = present @String "key" . present n
