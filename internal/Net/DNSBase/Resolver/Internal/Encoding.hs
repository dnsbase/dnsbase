{-# LANGUAGE RecordWildCards #-}
module Net.DNSBase.Resolver.Internal.Encoding
    ( encodeQuestion
    , encodeQuestionLP
    ) where

import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.EDNS
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Flags
import Net.DNSBase.Internal.Message
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.Util
import Net.DNSBase.Resolver.Internal.Types

makeEDNS :: EDNS -> QueryControls -> Maybe EDNS
makeEDNS EDNS{..} ctl
    | EdnsDisabled <- ctl = Nothing
    | ver <- case ctl of { EdnsVersion vn -> vn; _ -> ednsVersion }
    , udp <- case ctl of { EdnsUdpSize sz -> sz; _ -> ednsUdpSize }
    , opt <- case ctl of { EdnsOptionCtl optf -> applyOptionCtl optf ednsOptions }
      = Just $ EDNS ver udp opt


_encodeQuestion :: (forall s. QueryID -> DNSFlags -> Maybe EDNS
                                      -> Question -> SPut s RData)
                -> (QueryID -> QueryControls -> Question
                            -> Either DNSError ByteString)
_encodeQuestion f = \qid qctl q ->
    let flg = makeQueryFlags qctl
        medns = makeEDNS defaultEDNS qctl
     in case encodeCompressed $ f qid flg medns q of
        Left err -> Left $ EncodeError $ EncodeContext err
        Right enc -> Right enc


-- | Encode a DNS question for UDP using the provided 'QueryID', producing either a DNS error
-- if the encoding failed, or a 'ByteString' consisting of the wire-form DNS request.
--
-- The 'QueryControls' parameter can be used to modify the default values of various
-- DNS flags, as well as to configure EDNS version, UDP size, and options, or to disable
-- EDNS entirely.
--
-- The caller is responsible for generating the 'QueryID' via a securely seeded
-- CSPRNG.
encodeQuestion :: QueryID       -- ^ Crypto random request id
               -> QueryControls -- ^ Query flag and EDNS overrides
               -> Question      -- ^ Query name and type
               -> Either DNSError ByteString
encodeQuestion = _encodeQuestion $ putRequest

-- | Encode a DNS question for TCP using the provided 'QueryID', producing either a DNS error
-- if the encoding failed, or a 'ByteString' consisting of the wire-form DNS request with
-- a 2-octet unsigned integral length prefix in network byte order.
--
-- The 'QueryControls' parameter can be used to modify the default values of various
-- DNS flags, as well as to configure EDNS version, UDP size, and options, or to disable
-- EDNS entirely.
--
-- The caller is responsible for generating the 'QueryID' via a securely seeded
-- CSPRNG.
encodeQuestionLP :: QueryID
                 -> QueryControls
                 -> Question
                 -> Either DNSError ByteString
encodeQuestionLP = _encodeQuestion $ passLen `compose4` putRequest
