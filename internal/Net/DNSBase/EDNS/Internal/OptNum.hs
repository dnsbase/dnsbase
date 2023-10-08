module Net.DNSBase.EDNS.Internal.OptNum
    ( OptNum( ..
            , LLQ
            , UL
            , NSID
            , DAU
            , DHU
            , N3U
            , ECS
            , EXPIRE
            , COOKIE
            , TCPKEEPALIVE
            , PADDING
            , CHAIN
            , KEYTAG
            , EDE
            , CLIENTTAG
            , SERVERTAG
            )
    ) where

import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

-- | EDNS Option Code (RFC 6891).
newtype OptNum = OptNum Word16
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

-- | [Long-lived queries](https://www.rfc-editor.org/rfc/rfc8764.html)
pattern LLQ             :: OptNum
pattern LLQ              = OptNum 1
-- | [Dynamic DNS Update Leases](https://datatracker.ietf.org/doc/html/draft-ietf-dnssd-update-lease-08#section-9)
pattern UL              :: OptNum
pattern UL               = OptNum 2
-- | [NSID](https://www.rfc-editor.org/rfc/rfc5001.html#section-4)
pattern NSID            :: OptNum
pattern NSID             = OptNum 3
-- | [DNSSEC Algorithm Understood](https://www.rfc-editor.org/rfc/rfc6975.html#section-8)
pattern DAU             :: OptNum
pattern DAU              = OptNum 5
-- | [DS Hash Understood](https://www.rfc-editor.org/rfc/rfc6975.html#section-8)
pattern DHU             :: OptNum
pattern DHU              = OptNum 6
-- | [NSEC3 Hash Understood](https://www.rfc-editor.org/rfc/rfc6975.html#section-8)
pattern N3U             :: OptNum
pattern N3U              = OptNum 7
-- | [Client Subnet](https://www.rfc-editor.org/rfc/rfc7871.html#section-8)
pattern ECS             :: OptNum
pattern ECS              = OptNum 8
-- | [Expire](https://www.rfc-editor.org/rfc/rfc7314.html#section-5)
pattern EXPIRE          :: OptNum
pattern EXPIRE           = OptNum 9
-- | [Cookie](https://www.rfc-editor.org/rfc/rfc7873.html#section-8)
pattern COOKIE          :: OptNum
pattern COOKIE           = OptNum 10
-- | [TCP Keepalive](https://www.rfc-editor.org/rfc/rfc7828.html#section-6)
pattern TCPKEEPALIVE    :: OptNum
pattern TCPKEEPALIVE     = OptNum 11
-- | [Padding](https://www.rfc-editor.org/rfc/rfc7830.html#section-5)
pattern PADDING         :: OptNum
pattern PADDING          = OptNum 12
-- | [DNSSEC Chain](https://www.rfc-editor.org/rfc/rfc7901.html#section-9)
pattern CHAIN           :: OptNum
pattern CHAIN            = OptNum 13
-- | [Key Tag](https://www.rfc-editor.org/rfc/rfc8145.html#section-6)
pattern KEYTAG          :: OptNum
pattern KEYTAG           = OptNum 14
-- | [EDNS Error](https://www.rfc-editor.org/rfc/rfc8914.html#section-5.1)
pattern EDE             :: OptNum
pattern EDE              = OptNum 15
-- | [Client Tag](https://datatracker.ietf.org/doc/html/draft-bellis-dnsop-edns-tags-01#section-7)
pattern CLIENTTAG       :: OptNum
pattern CLIENTTAG        = OptNum 16
-- | [Client Tag](https://datatracker.ietf.org/doc/html/draft-bellis-dnsop-edns-tags-01#section-7)
pattern SERVERTAG       :: OptNum
pattern SERVERTAG        = OptNum 17

instance Presentable OptNum where
    present LLQ          = present "LLQ"
    present UL           = present "UL"
    present NSID         = present "NSID"
    present DAU          = present "DAU"
    present DHU          = present "DHU"
    present N3U          = present "N3U"
    present ECS          = present "ECS"
    present EXPIRE       = present "EXPIRE"
    present COOKIE       = present "COOKIE"
    present TCPKEEPALIVE = present "TCPKEEPALIVE"
    present PADDING      = present "PADDING"
    present CHAIN        = present "CHAIN"
    present KEYTAG       = present "CHAIN"
    present EDE          = present "EDE"
    present CLIENTTAG    = present "CLIENTTAG"
    present SERVERTAG    = present "SERVERTAG"
    present oc           = present "OPTION" . present (coerce @_ @Word16 oc)
