{-# LANGUAGE RecordWildCards #-}
module Net.DNSBase.Internal.SockIO (
    -- * Receiving DNS messages
    receiveUDP
  , receiveTCP
    -- * Sending pre-encoded DNS messages
  , sendUDP
  , sendTCP
  ) where

import qualified Data.ByteString as B
import qualified Network.Socket.ByteString as Socket
import Network.Socket (Socket)
import Network.Socket.ByteString (recv)
import System.IO.Error (tryIOError, mkIOError, eofErrorType)

import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Util
import Net.DNSBase.Resolver.Internal.Types

----------------------------------------------------------------

-- | Receive and a single 'DNSMessage' over a UDP 'Socket'.  Messages
-- longer than 'maxUdpSize' are silently truncated, but this should not occur
-- in practice, since we cap the advertised EDNS UDP buffer size limit at the
-- same value.  A 'DNSError' is raised if the I/O operation fails.
--
receiveUDP :: Word16 -> Socket -> DNSIO B.ByteString
receiveUDP maxudp sock = withExceptT wrapError $ recv' sock bufsiz
  where
    bufsiz = fromIntegral maxudp
    wrapError = NetworkError . NetworkFailure

recv' :: Socket -> Int -> ExceptT IOError IO ByteString
recv' sock bufsiz = ExceptT $ tryIOError $ recv sock bufsiz

-- | Receive a single DNS message over a virtual-circuit (TCP) connection.  It
-- is up to the caller to implement any desired timeout. An 'DNSError' is
-- raised if the I/O operation fails.
--
receiveTCP :: Socket -> DNSIO B.ByteString
receiveTCP sock = recvDNS sock 2 >>= recvDNS sock . toLen
  where
    toLen :: ByteString -> Int
    toLen = fromIntegral . word16be

recvDNS :: Socket -> Int -> DNSIO ByteString
recvDNS sock len = withExceptT wrapError recv1
  where
    wrapError = NetworkError . NetworkFailure

    recv1 :: ExceptT IOError IO ByteString
    recv1 = recvCore len >>= cond (B.length .= len) return loop

    loop :: ByteString -> ExceptT IOError IO ByteString
    loop bs0 = do
        let left = len - B.length bs0
        bs1 <- recvCore left
        cond (B.length .= len) return loop $! bs0 <> bs1

    eofE = mkIOError eofErrorType "connection terminated" Nothing Nothing

    recvCore :: Int -> ExceptT IOError IO ByteString
    recvCore len0 = recv' sock len0
                >>= cond B.null (const $ throwE eofE) return

----------------------------------------------------------------

-- | Send an encoded 'DNSMessage' datagram over UDP.  The socket must be
-- explicitly connected to the destination nameserver.  The message length is
-- implicit in the size of the UDP datagram.  With TCP you must use 'sendTCP',
-- because TCP does not have message boundaries, and each message needs to be
-- prepended with an explicit length.
--
sendUDP :: Socket -> ByteString -> DNSIO ()
sendUDP sock = lift . void . Socket.send sock

-- | Send one or more encoded 'DNSMessage' buffers over TCP, each already
-- encapsulated with an explicit length prefix and then concatenated into a
-- single buffer.  DO NOT use 'sendTCP' with UDP.
--
sendTCP :: Socket -> ByteString -> DNSIO ()
sendTCP vc = lift . Socket.sendAll vc
