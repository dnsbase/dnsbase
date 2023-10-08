{-# LANGUAGE RecordWildCards #-}
module Net.DNSBase.Internal.Error
    ( DNSError(..)
    , DecodeContext(..)
    , DnsSection(..)
    , NetworkContext(..)
    , ProtocolContext(..)
    , UserContext(..)
    , EncodeErr(..)
    , EncodeContext(..)
    ) where

import qualified Data.Type.Equality as R
import qualified Type.Reflection as R
import Control.Exception (Exception, IOException)

import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.Peer
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.RCODE (RCODE)
import Net.DNSBase.Internal.RRTYPE (RRTYPE)
import Net.DNSBase.Internal.Util

-- | DNS API errors.
--
data DNSError
    = BadConfiguration String
      -- ^ Resolver misconfiguration.
    | BadNameserver IOException
      -- ^ Nameserver name -> address lookup failure.
    | DecodeError DecodeContext String
      -- ^ Error while decoding from wire form.
    | EncodeError EncodeContext
      -- ^ Error while encoding to wire form.
    | InvalidDomain String
      -- ^ Invalid domain name presentation form.
    | NetworkError NetworkContext
      -- ^ Error in connection establishment, data transmission or a timeout.
    | ProtocolError ProtocolContext
      -- ^ Unexpected DNS message.
    | ResponseError RCODE
      -- ^ DNS message indicates a remote error condition.
    | UserError UserContext
      -- ^ Invalid request.
    deriving (Eq, Typeable)

instance Exception DNSError
instance Show DNSError where
    showsPrec _ (BadConfiguration rc) = showString "Configuration error: " .
                                        showString rc
    showsPrec _ (BadNameserver io)    = showString "Unusable nameserver: " .
                                        shows io
    showsPrec _ (DecodeError ctx str) = showString "Decode error: " .
                                        presentString ctx . showChar ' ' . showString str
    showsPrec _ (EncodeError ec)      = showString "encoding error: " .
                                        shows ec
    showsPrec _ (InvalidDomain ed)    = showString "invalid domain: " .
                                        showString ed
    showsPrec _ (NetworkError en)     = shows en
    showsPrec _ (ProtocolError ep)    = shows ep
    showsPrec _ (ResponseError rc)    = showString "server error: rcode = " .
                                        showString (presentString rc mempty)
    showsPrec _ (UserError eu)        = shows eu

----------------------------------------------------------------

-- | Request or response context in which a failure occurred.  The
-- `decodeTriple` holds the name, class and type of the problem RR, provided
-- the error was not in one of those fields.
data DecodeContext
    = DecodeContext
    { decodeSection :: DnsSection
    , decodeSource  :: Maybe MessageSource
    , decodeTriple  :: Maybe DnsTriple
    } deriving (Eq)

instance Presentable DecodeContext where
    present DecodeContext {..} =
        maybe id ((present @String "from" .) . presentSp) decodeSource
        . presentSp @String "in" . presentSp decodeSection
        . maybe id ((presentSp @String "at" .) . presentSp) decodeTriple

-- | Message /section/ for error reporting.  The message header and EDNS @OPT@
-- record are also considered /sections/ in this context.
data DnsSection
    = DnsHeaderSection
      -- ^ While parsing the message header.
    | DnsQuestionSection
      -- ^ While parsing the question section.
    | DnsAnswerSection
      -- ^ While parsing the answer section.
    | DnsAuthoritySection
      -- ^ While parsing the authority section.
    | DnsAdditionalSection
      -- ^ While parsing the additional section.
    | DnsEDNSSection
      -- ^ While parsing the EDNS OPT record.
    | DnsNonSection
      -- ^ While parsing a wire-form message fragment.
  deriving (Eq, Show)

instance Presentable DnsSection where
    present DnsHeaderSection     = present @String "the message header"
    present DnsQuestionSection   = present @String "the question section"
    present DnsAnswerSection     = present @String "the answer section"
    present DnsAuthoritySection  = present @String "the authority section"
    present DnsAdditionalSection = present @String "the additional section"
    present DnsEDNSSection       = present @String "an EDNS OPT pseudo-RR"
    present DnsNonSection        = present @String "a wire-form fragment"

----------------------------------------------------------------

data NetworkContext =
    -- | The number of retries for the request was exceeded.
    RetryLimitExceeded
    -- | TCP fallback request timed out.
  | TimeoutExpired
    -- | Network failure.
  | NetworkFailure IOException
  | ServerFailure
  deriving (Eq, Show)

data ProtocolContext =
    -- ^ The sequence number of the answer doesn't match our query. This
    --   could indicate foul play.
    SequenceNumberMismatch
    -- ^ The question section of the response doesn't match our query. This
    --   could indicate foul play.
  | QuestionMismatch
  deriving (Eq, Show)

data UserContext =
    -- | The RRTYPE requested is invalid for queries.
    InvalidQueryType RRTYPE
    -- | The domain for query is illegal.
  | IllegalDomain String
    -- | The response message question count is not equal to 1.
  | BadResponseQuestionCount Int
  deriving (Eq, Show)

----------------------------------------------------------------

-- | Encoding error, polymorphic over the context type
data EncodeErr r where
    -- | message or field too long
    EncodeTooLong :: (Typeable r, Show r, Eq r) => r -> EncodeErr r
    -- | Invalid input
    CantEncode    :: (Typeable r, Show r, Eq r) => r -> EncodeErr r
    -- | Unencodable reserved type
    ReservedType  :: (Typeable r, Show r, Eq r) => RRTYPE -> r -> EncodeErr r
    -- | RCODE or flags require EDNS
    EDNSRequired  :: EncodeErr r

deriving instance (Eq r) => Eq (EncodeErr r)
deriving instance (Show r) => Show (EncodeErr r)
deriving instance (Typeable r) => Typeable (EncodeErr r)

data EncodeContext = forall r. (Typeable r, Show r, Eq r) => EncodeContext (EncodeErr r)

instance Show EncodeContext where
    show (EncodeContext err) = show err

instance Eq EncodeContext where
    (EncodeContext (EncodeTooLong a)) == (EncodeContext (EncodeTooLong b)) =
        case R.testEquality (R.typeOf a) (R.typeOf b) of
            Just R.Refl -> a == b
            _           -> False
    (EncodeContext (CantEncode a)) == (EncodeContext (CantEncode b)) =
        case R.testEquality (R.typeOf a) (R.typeOf b) of
            Just R.Refl -> a == b
            _           -> False
    (EncodeContext EDNSRequired) == (EncodeContext EDNSRequired) = True
    _ == _ = False
