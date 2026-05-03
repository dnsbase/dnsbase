{-|
Module      : Net.DNSBase.EDNS.Option.NSID
Description : EDNS Name Server Identifier option (RFC 5001)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The NSID EDNS option lets a server identify itself in a reply
— useful for distinguishing between members of an anycast set.
The client sends an empty NSID option to request identification;
the server's reply carries an opaque byte string chosen by the
operator (typically a host name or short tag).
-}

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

-- | The NSID EDNS option
-- ([RFC 5001](https://datatracker.ietf.org/doc/html/rfc5001))
-- — opaque server-chosen bytes identifying the responder.
-- The same option code is used in both directions: a client sends
-- an empty value to ask for identification, the server replies
-- with its identifier (which may contain arbitrary bytes,
-- including non-printable ones).
--
-- The 'Presentable' instance renders the bytes through 'DnsText',
-- producing a quoted character-string when the content is
-- printable and escapes for any non-printable bytes.
newtype O_nsid = O_NSID ShortByteString deriving (Eq, Show)

instance Presentable O_nsid where
    -- | Though NSID is an opaque 'ShortByteString', we attempt to present
    -- it as a character string.
    present (O_NSID val) = coerce (present @DnsText) val

instance KnownEdnsOption O_nsid where
    optNum _ = NSID
    {-# INLINE optNum #-}
    optEncode (O_NSID bs) = putShortByteString bs
    optDecode _ _ = EdnsOption . O_NSID <.> getShortNByteString
