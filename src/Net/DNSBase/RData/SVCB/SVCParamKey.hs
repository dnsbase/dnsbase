module Net.DNSBase.RData.SVCB.SVCParamKey where

import Data.Word (Word16)

import Net.DNSBase.Present


-- | [SvcParamKey](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-12#section-2.1)
--
-- The initially registered keys are listed in:
-- <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-12#section-14.3.2>
newtype SVCParamKey = SVCParamKey Word16
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

pattern MANDATORY     :: SVCParamKey ; pattern MANDATORY     = SVCParamKey 0
pattern ALPN          :: SVCParamKey ; pattern ALPN          = SVCParamKey 1
pattern NODEFAULTALPN :: SVCParamKey ; pattern NODEFAULTALPN = SVCParamKey 2
pattern PORT          :: SVCParamKey ; pattern PORT          = SVCParamKey 3
pattern IPV4HINT      :: SVCParamKey ; pattern IPV4HINT      = SVCParamKey 4
pattern ECH           :: SVCParamKey ; pattern ECH           = SVCParamKey 5
pattern IPV6HINT      :: SVCParamKey ; pattern IPV6HINT      = SVCParamKey 6
pattern DOHPATH       :: SVCParamKey ; pattern DOHPATH       = SVCParamKey 7
pattern OHTTP         :: SVCParamKey ; pattern OHTTP         = SVCParamKey 8

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
    present (SVCParamKey n) = present @String "key" . present n
