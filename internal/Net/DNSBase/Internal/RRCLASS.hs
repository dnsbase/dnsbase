module Net.DNSBase.Internal.RRCLASS
    ( RRCLASS( ..
             , IN
             , CS
             , CHAOS
             , HESIOD
             , NONE
             , ANYCLASS
             )
    ) where

import Data.Hashable (Hashable(..))
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util


-- | DNS query or resource record class.
newtype RRCLASS = RRCLASS Word16
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Hashable, Show, Read)

instance Presentable RRCLASS where
    present IN       = present @String "IN"
    present CS       = present @String "CS"
    present CHAOS    = present @String "CHAOS"
    present HESIOD   = present @String "HESIOD"
    present NONE     = present @String "NONE"
    present ANYCLASS = present @String "*"
    present c        = present @String "CLASS" . present @Word16 (coerce c)

-- | IN class, <https://tools.ietf.org/html/rfc1035#section-3.2.4>
pattern IN        :: RRCLASS;     pattern IN        = RRCLASS 1

-- | CS class (obsolete), <https://tools.ietf.org/html/rfc1035#section-3.2.4>
pattern CS        :: RRCLASS;     pattern CS        = RRCLASS 2

-- | CHAOS class, <https://tools.ietf.org/html/rfc1035#section-3.2.4>
pattern CHAOS     :: RRCLASS;     pattern CHAOS     = RRCLASS 3

-- | HESIOD class, <https://tools.ietf.org/html/rfc1035#section-3.2.4>
pattern HESIOD    :: RRCLASS;     pattern HESIOD    = RRCLASS 4

-- | NONE class (Only used in the update protocol),
-- <https://tools.ietf.org/html/rfc2136>
pattern NONE      :: RRCLASS;     pattern NONE      = RRCLASS 254

-- | ANYCLASS (valid only as a query class),
-- <https://tools.ietf.org/html/rfc1035#section-3.2.5>
pattern ANYCLASS  :: RRCLASS;     pattern ANYCLASS  = RRCLASS 255
