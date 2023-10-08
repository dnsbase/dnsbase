{-# LANGUAGE RecordWildCards #-}
module Net.DNSBase.Internal.Peer
    ( MessageSource(..)
    , DnsXprt ( DnsOverUDP
              , DnsOverTCP
              , DnsOverTLS
              , DnsOverQUIC
              )
    ) where
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

-- | Transport between DNS client and server
newtype DnsXprt = DnsXprt Word8
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral)

instance Presentable DnsXprt where
    present DnsOverUDP  = present @String "UDP"
    present DnsOverTCP  = present @String "TCP"
    present DnsOverTLS  = present @String "DoT"
    present DnsOverQUIC = present @String "DoQ"
    present t           = present @String "Xprt" . present @Word8 (coerce t)

pattern DnsOverUDP  :: DnsXprt; pattern DnsOverUDP  = DnsXprt 0
pattern DnsOverTCP  :: DnsXprt; pattern DnsOverTCP  = DnsXprt 1
pattern DnsOverTLS  :: DnsXprt; pattern DnsOverTLS  = DnsXprt 2
pattern DnsOverQUIC :: DnsXprt; pattern DnsOverQUIC = DnsXprt 3

-- | DNS client or server peer endpoint.
data MessageSource = MessageSource
    { dnsPeerXprt :: DnsXprt
    , dnsPeerName :: Maybe String
    , dnsPeerAddr :: IP
    , dnsPeerPort :: Word16
    } deriving (Eq)

instance Presentable MessageSource where
    present MessageSource {..} =
        present dnsPeerXprt . present '@'
        . maybe id present dnsPeerName
        . presentCharSep '[' dnsPeerAddr . present ']'
        . presentCharSep ':' dnsPeerPort
