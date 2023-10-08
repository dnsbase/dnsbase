module Net.DNSBase.Internal.Error
    ( DNSError(..)
    , NetworkContext(..)
    , ProtocolContext(..)
    , UserContext(..)
    , EncodeErr(..)
    , EncodeContext(..)
    ) where

import qualified Data.Type.Equality as R
import qualified Type.Reflection as R
import Control.Exception (Exception, IOException)

import Net.DNSBase.Internal.RRTYPE (RRTYPE)
import Net.DNSBase.Internal.RCODE (RCODE)
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

type DecodeContext = String
type SystemContext = String

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
    -- | The sequence number of the answer doesn't match our query. This
    --   could indicate foul play.
    SequenceNumberMismatch
    -- | The question section of the response doesn't match our query. This
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

type ResolverContext = String

-- | An enumeration of all possible DNS errors that can occur.
data DNSError = BadConfiguration ResolverContext
              | BadNameserver IOException
              | DecodeError DecodeContext
              | EncodeError EncodeContext
              | InvalidDomain String
              | NetworkError NetworkContext
              | ProtocolError ProtocolContext
              | ResponseError RCODE
              | SystemError SystemContext
              | UserError UserContext
              deriving (Eq, Typeable)

instance Exception DNSError
instance Show DNSError where
    showsPrec _ (BadConfiguration rc) = showString "Configuration error: " .
                                        showString rc
    showsPrec _ (BadNameserver io)    = showString "Unusable nameserver: " .
                                        shows io
    showsPrec _ (DecodeError ed)      = showString "decoding error: " .
                                        showString ed
    showsPrec _ (EncodeError ec)      = showString "encoding error: " .
                                        shows ec
    showsPrec _ (InvalidDomain ed)    = showString "invalid domain: " .
                                        showString ed
    showsPrec _ (NetworkError en)     = shows en
    showsPrec _ (ProtocolError ep)    = shows ep
    showsPrec _ (ResponseError rc)    = showString "server error: rcode = " .
                                        showString (presentString rc mempty)
    showsPrec _ (SystemError es)      = showString "system error: " .
                                        showString es
    showsPrec _ (UserError eu)        = shows eu

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
