module Net.DNSBase.EDNS.Option.NSID
    ( O_nsid(..)
    ) where

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.EDNS.Internal.OptNum
import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Text
import Net.DNSBase.Internal.Util

-- | Name Server Identifier (RFC5001).  Bidirectional, empty from client.
-- (opaque octet-string).  May contain binary data, which MUST be empty in
-- queries.
newtype O_nsid = O_NSID ShortByteString deriving (Typeable, Eq, Show)

instance Presentable O_nsid where
    -- | Though NSID is an opaque 'ShortByteString', we attempt to present
    -- it as a character string.
    present (O_NSID val) = coerce (present @DnsText) val

instance EdnsOption O_nsid where
    optNum _ = NSID
    {-# INLINE optNum #-}
    optEncode (O_NSID bs) = putShortByteString bs
    optDecode _ len = SomeOption . O_NSID <$> getShortNByteString len
