{-# LANGUAGE
    OverloadedStrings
  , RecordWildCards
  #-}
module Net.DNSBase.Internal.Transport
    ( lookupRawCtl
    ) where

import qualified Data.IP as IP
import Control.Exception (bracket)
import Network.Socket (AddrInfo(..), SockAddr(..), Family(AF_INET, AF_INET6))
import Network.Socket (Socket, SocketType(Stream) , close, socket, connect)
import Network.Socket (defaultProtocol)
import System.IO.Error (annotateIOError)
import System.Timeout (timeout)
import Time.System (timeCurrent)
import Time.Types (Elapsed(..), Seconds(..))

import Net.DNSBase.Decode.Internal.Message
import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.EDNS
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Flags
import Net.DNSBase.Internal.Message
import Net.DNSBase.Internal.Peer
import Net.DNSBase.Internal.RCODE
import Net.DNSBase.Internal.RRCLASS
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.SockIO
import Net.DNSBase.Internal.Util
import Net.DNSBase.Resolver.Internal.Encoding
import Net.DNSBase.Resolver.Internal.Types

-- | Check response for a matching identifier and question.  If we ever do
-- pipelined TCP, we'll need to handle out of order responses.  See:
-- https://tools.ietf.org/html/rfc7766#section-7
--
checkResp :: Question -> QueryID -> DNSMessage -> Bool
checkResp q qid = isNothing . checkRespM q qid

-- When the response 'RCODE' is 'FORMERR', the server did not understand our
-- query packet, and so is not expected to return a matching question.
--
checkRespM :: Question -> QueryID -> DNSMessage -> Maybe DNSError
checkRespM q qid DNSMessage{..}
  | dnsMsgId /= qid = Just $ ProtocolError SequenceNumberMismatch
  | FORMERR <- dnsMsgRC
  , []        <- dnsMsgQu    = Nothing
  | [q] /= dnsMsgQu          = Just $ ProtocolError QuestionMismatch
  | otherwise                = Nothing

----------------------------------------------------------------

type Retries = Int
type Timeout = Int

type TcpLookup = Timeout -> Question -> QueryControls -> ResolverConf -> DNSIO DNSMessage
type UdpLookup = Retries -> TcpLookup

timeout' :: Timeout -> DNSIO a -> DNSIO (Maybe a)
timeout' tmout act = ExceptT $ sequenceA <$> (timeout tmout $ runExceptT act)

bracket' :: DNSIO a -> (a -> IO b) -> (a -> DNSIO c) -> DNSIO c
bracket' get end act = ExceptT $ bracket (runExceptT get) end' act'
  where
    end' = \case
      Left _ -> return ()
      Right x -> void $ end x
    act' = \case
      Left err -> return $ Left err
      Right x  -> runExceptT $ act x

-- In lookup loop, we try UDP until we get a response.  If the response
-- is truncated, we try TCP once, with no further UDP retries.
--
-- For now, we optimize for low latency high-availability caches
-- (e.g.  running on a loopback interface), where TCP is cheap
-- enough.  We could attempt to complete the TCP lookup within the
-- original time budget of the truncated UDP query, by wrapping both
-- within a a single 'timeout' thereby staying within the original
-- time budget, but it seems saner to give TCP a full opportunity to
-- return results.  TCP latency after a truncated UDP reply will be
-- atypical.
--
-- Future improvements might also include support for TCP on the
-- initial query.
--
-- This function merges the query flag overrides from the resolver
-- configuration with any additional overrides from the caller.
--
lookupRawCtl :: Resolver -> QueryControls -> Domain -> RRCLASS -> RRTYPE -> DNSIO DNSMessage
lookupRawCtl Resolver{..} qctls dom qclass qtype
  | isIllegalQT qtype = throwE $ UserError $ InvalidQueryType qtype
  | otherwise = case seedServers resolvSeed of
      ns :| [] -> resolveOne ns resolvRng retry tmout q ctls conf
      nss      -> resolveSeq nss resolvRng retry tmout q ctls conf
  where
    conf           = seedConfig resolvSeed
    tmout          = rcTimeout conf
    retry          = rcRetries conf
    ctls           = qctls <> rcQryCtls conf
    q              = DnsTriple dom qtype qclass

    isIllegalQT (RRTYPE 0) = True
    isIllegalQT AXFR = True
    isIllegalQT IXFR = True
    isIllegalQT RRSIG = True
    isIllegalQT OPT = True
    isIllegalQT typ = typ >= NXNAME && typ < MAILB


resolveSeq :: NonEmpty Nameserver -> IO QueryID -> UdpLookup
resolveSeq nss gen retry tmout q qctls conf = loop nss
  where
    loop (ns :| []) = resolveOne ns gen retry tmout q qctls conf
    loop (ns :| ns' : rest) =
        resolveOne ns gen retry tmout q qctls conf
            `catchE` const (loop (ns' :| rest))

-- UDP attempts must use the same ID and accept delayed answers
-- but we use a fresh ID for each TCP lookup.
--
resolveOne :: Nameserver -> IO QueryID -> UdpLookup
resolveOne ns gen retry tmout q qctls conf = do
    ident <- lift gen
    udpLookup ns ident retry tmout q qctls conf

----------------------------------------------------------------

ioErrorToDNSError :: Nameserver -> String -> DNSError -> DNSIO DNSMessage
ioErrorToDNSError ns protoName = \case
    NetworkError (NetworkFailure err) ->
      let loc  = protoName ++ "@" ++ show ns
          err' = annotateIOError err loc Nothing Nothing
       in throwE $ NetworkError $ NetworkFailure err'
    err -> throwE err

----------------------------------------------------------------

udpOpen :: AddrInfo -> DNSIO Socket
udpOpen ai = lift $ do
    sock <- socket (addrFamily ai) (addrSocketType ai) (addrProtocol ai)
    connect sock (addrAddress ai)
    return sock

-- | Enabled unless explicitly disabled.
hasEDNS :: QueryControls -> Bool
hasEDNS EdnsDisabled = False
hasEDNS _            = True

-- | Perform a UDP lookup, retrying over TCP on TC=1 or without EDNS on FORMERR.
--
-- XXX: With multiple available IP endpoints, the retry strategy is suboptimal,
-- we should try another server before trying the same server again!
--
udpLookup :: Nameserver -> QueryID -> UdpLookup
udpLookup ns ident retry tmout q qctls conf =
    case encodeQuestion ident qctls q of
      Left err -> throwE err
      Right qry -> do
        flip catchE (ioErrorToDNSError ns "udp") $
            bracket' do udpOpen (nsAddr ns)
                     do close
                     do \sock -> loop sock 0 qry qctls
  where
    loop sock !ntries qry ctls
      | ntries == retry = throwE $ NetworkError RetryLimitExceeded
      | otherwise       = do
          mres <- timeout' tmout (sendUDP sock qry >> getAns ctls sock)
          case mres of
              Nothing  -> loop sock (ntries + 1) qry ctls
              Just res -> do
                      let fl = dnsMsgFl res
                          tc = hasAnyFlags TCflag fl
                          rc = dnsMsgRC res
                          eh = dnsMsgEx res
                          cs = EdnsDisabled <> ctls
                      if | tc -> tcpLookup ns ident tmout q qctls conf
                         | rc == FORMERR && isNothing eh && hasEDNS ctls
                         , False <- hasAnyFlags DOflag $ makeQueryFlags qctls
                         , Right qry' <- encodeQuestion ident cs q
                            -- Retry without EDNS when DNSSEC was not requested
                            -- and a non-EDNS response to an EDNS query
                            -- returned FORMERR.
                         -> loop sock ntries qry' cs
                         | otherwise -> pure res

    -- | Closed UDP ports are occasionally re-used for a new query, with
    -- the nameserver returning an unexpected answer to the wrong socket.
    -- Such answers should be simply dropped, with the client continuing
    -- to wait for the right answer, without resending the question.
    -- Note, this eliminates sequence mismatch as a UDP error condition,
    -- instead we'll time out if no matching answer arrives.
    --
    getAns :: QueryControls -> Socket -> DNSIO DNSMessage
    getAns ctls sock = do
        bs <- receiveUDP maxsz sock
        msg <- decodeMsg bs conf DnsOverUDP ns
        if | checkResp q ident msg -> pure msg
           | otherwise             -> getAns ctls sock
      where
        maxsz | EdnsDisabled   <- ctls = minUdpSize
              | EdnsUdpSize sz <- ctls = sz
              | otherwise = ednsUdpSize defaultEDNS

----------------------------------------------------------------

-- Create a TCP socket with the given socket address.
tcpOpen :: SockAddr -> DNSIO Socket
tcpOpen peer = case peer of
    SockAddrInet{}  -> lift $ socket AF_INET  Stream defaultProtocol
    SockAddrInet6{} -> lift $ socket AF_INET6 Stream defaultProtocol
    _               -> throwE $ NetworkError ServerFailure

-- Perform a DNS query over TCP, if we were successful in creating
-- the TCP socket.
-- This throws DNSError only.
tcpLookup :: Nameserver -> QueryID -> TcpLookup
tcpLookup ns ident tmout q qctls conf =
    flip catchE (ioErrorToDNSError ns "tcp") $ do
        res <- bracket' do tcpOpen $ addrAddress $ nsAddr ns
                        do close
                        do perform qctls
        let rc = dnsMsgRC res
            eh = dnsMsgEx res
            cs = EdnsDisabled <> qctls
        -- If we first tried with EDNS, retry without on FORMERR.
        -- XXX: Move the retry into "perform", where we can reuse
        -- the same connection.
        if | rc == FORMERR && isNothing eh
           , EdnsEnabled <- qctls
             -> bracket' (tcpOpen addr) close (perform cs)
           | otherwise
             -> pure res
  where
    addr = addrAddress $ nsAddr ns
    perform ctls sock =
        case encodeQuestionLP ident ctls q of
            Left err -> throwE err
            Right qry -> do
                mres <- timeout' tmout $ do
                    lift $ connect sock addr
                    sendTCP sock qry
                    receiveTCP sock
                case mres of
                    Nothing -> throwE $ NetworkError TimeoutExpired
                    Just bs -> do
                        msg <- decodeMsg bs conf DnsOverTCP ns
                        maybe (pure msg) throwE $ checkRespM q ident msg

decodeMsg :: ByteString
          -> ResolverConf
          -> DnsXprt
          -> Nameserver
          -> DNSIO DNSMessage
decodeMsg bs conf dnsPeerXprt ns@(addrAddress . nsAddr -> SockAddrInet sin_port sin_addr) = do
    Elapsed (Seconds now) <- lift timeCurrent
    either throwE pure $ decodeAtWith now True dec bs
  where
    dnsPeerAddr = IP.IPv4 $ IP.fromHostAddress sin_addr
    dnsPeerPort = fromIntegral sin_port
    dnsPeerName = nsName ns
    dec = local (setDecodeSource MessageSource{..})
                (getMessage (rcRDataMap conf) (rcOptnMap conf))

decodeMsg bs conf dnsPeerXprt ns@(addrAddress . nsAddr -> SockAddrInet6 sin6_port _ sin6_addr _) = do
    Elapsed (Seconds now) <- lift timeCurrent
    either throwE pure $ decodeAtWith now True dec bs
  where
    dnsPeerAddr = IP.IPv6 $ IP.fromHostAddress6 sin6_addr
    dnsPeerPort = fromIntegral sin6_port
    dnsPeerName = nsName ns
    dec = local (setDecodeSource MessageSource{..})
                (getMessage (rcRDataMap conf) (rcOptnMap conf))

decodeMsg bs conf _ _ = do
    Elapsed (Seconds now) <- lift timeCurrent
    either throwE pure $ decodeAtWith now True dec bs
  where
    dec = getMessage (rcRDataMap conf) (rcOptnMap conf)
