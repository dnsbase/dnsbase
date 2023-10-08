module Net.DNSBase.Message
    ( -- * DNS Message data type
      DNSMessage(..)
    , Question(..)
    , QueryID
    , putMessage
    , putRequest
    ) where

import Net.DNSBase.Internal.Message
