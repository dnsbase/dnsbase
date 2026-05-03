-- |
-- Module      : Net.DNSBase.Internal.EDNS
-- Description : TBD
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
module Net.DNSBase.Internal.EDNS
    ( -- * Fixed portion of EDNS(0) OPT pseudo-RR
      EDNS(..)
    , defaultEDNS
    , maxUdpSize
    , minUdpSize
    ) where

import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.Internal.Util

----------------------------------------------------------------
-- EDNS (RFC 6891, EDNS(0))
----------------------------------------------------------------

-- | Data type representing extension fields of a version @0@
-- [EDNS](https://tools.ietf.org/html/rfc6891) message.  When a single EDNS(0)
-- @OPT@ pseudo-RR is present in the additional section of a DNS message, it is
-- processed as an @EDNS(0)@ extension header.  The @OPT@ pseudo-RR@ is then
-- elided from the additional section of the decoded message.
--
-- The EDNS @OPT@ pseudo-RR augments the message error status with an 8-bit
-- field that together with the 4-bit @RCODE@ from the unextended DNS header
-- forms the full 12-bit extended @RCODE@.  In order to avoid potential
-- misinterpretation of the response @RCODE@, when the OPT record is decoded,
-- the upper eight bits of the error status are combined with the @RCODE@ of
-- the basic message header to form a single 12-bit result.  The decoded 'EDNS'
-- pseudo-header, omits the extended @RCODE@ bits, they are instead found in
-- the upper eight bits of the message @RCODE@.
--
-- Likewise, when decoding EDNS messages the extension flags are folded into
-- the upper 16-bits of an extended 32-bit @flags@ field in the message header.
-- Consequently, the 'EDNS' extension header record needs no extension @RCODE@
-- or @flags@ fields.
--
-- The reverse process occurs when encoding messages.  The low four bits of the
-- message header @RCODE@ are encoded into the basic DNS header, while the
-- upper eight bits are encoded as part of the EDNS @OPT@ pseudo-RR.
-- Similarly, the high 16 bits of the flags are also encoded in the @OPT@
-- pseudo-RR.  Encoding of messages with an @RCODE@ larger than 15 or any
-- extension flags set fails unless EDNS is enabled.
--
-- When encoding messages for transmission, the 'EDNS' extension header is used
-- to generate the additional OPT record.  Do not add explicit @OPT@ records to
-- the additional section, instead configure EDNS via the message 'Net.DNSBase.Message.ednsHeader'
-- field.
--
-- The fixed part of an @OPT@ pseudo-RR is structured as follows
-- ([RFC891 6.1.2](<https://tools.ietf.org/html/rfc6891#section-6.1.2>)):
--
-- > +------------+--------------+------------------------------+
-- > | Field Name | Field Type   | Description                  |
-- > +------------+--------------+------------------------------+
-- > | NAME       | domain name  | MUST be 0 (root domain)      |
-- > | TYPE       | u_int16_t    | OPT (41)                     |
-- > | CLASS      | u_int16_t    | requestor's UDP payload size |
-- > | TTL        | u_int32_t    | extended RCODE and flags     |
-- > | RDLEN      | u_int16_t    | length of all RDATA          |
-- > | RDATA      | octet stream | {attribute,value} pairs      |
-- > +------------+--------------+------------------------------+
--
-- The extended RCODE and flags, which OPT stores in the RR Time to Live
-- (TTL) field, are structured as follows
-- ([RFC6891 6.1.3](<https://tools.ietf.org/html/rfc6891#section-6.1.3>)):
--
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- > |          EXTENDED-RCODE       |             VERSION           |
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- > | DO|                             Z                             |
-- > +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
--
data EDNS = EDNS {
    -- | EDNS version, presently only version 0 is defined.
    ednsVersion :: {-# UNPACK #-} Word8
    -- | Supported UDP payload size.
  , ednsUdpSize  :: {-# UNPACK #-} Word16
    -- | EDNS options (e.g. 'Net.DNSBase.EDNS.Option.NSID.O_nsid', ...), corresponding to the (attribute,
    -- value) pairs in the RDATA field of the @OPT@ psuedo-RR.
  , ednsOptions  :: [EdnsOption]
  } deriving (Eq, Show)

-- | The default EDNS pseudo-header for queries.  In accordance
-- with the recommendation in
-- [RFC9715, Appedix A](https://datatracker.ietf.org/doc/html/rfc9715#appendix-A-3)
-- the UDP buffer size defaults to 1400 bytes, this should result
-- in replies that fit into both the IPv4 and IPv6 MTU in typical
-- Internet-connected networks.
--
-- A small minority of IPv6 networks are rumoured to have smaller
-- MTUs of around 1280 bytes, and the corresponding DNS UDP size
-- might then be 1232 bytes.
--
-- Since this library is a stub resolver, it is expected that the
-- configured iterative resolvers are "near" enough to not require
-- pessimistic UDP size limits.  With a loopback conenction to a
-- local resolver it may even make sense to set the UDP size limit
-- at the 16KB maximum.
--
-- There is no single best value for the buffer size, too large
-- risks fragmentation issues, while too small risks TCP fallback
-- which is more costly and may fail.
--
-- @
-- defaultEDNS = EDNS
--     { ednsVersion = 0      -- The default EDNS version is 0
--     , ednsUdpSize = 1400   -- RFC9715 recommended value
--     , ednsOptions = []     -- No EDNS options by default
--     }
-- @
--
defaultEDNS :: EDNS
defaultEDNS = EDNS
    { ednsVersion = 0      -- ^ The default EDNS version is 0
    , ednsUdpSize = 1400   -- ^ IPv6-safe UDP MTU
    , ednsOptions = []     -- ^ No EDNS options by default
    }

-- | Maximum UDP size that can be advertised.  If the 'ednsUdpSize' of 'EDNS'
--   is larger, then this value is sent instead.  This value is likely to work
--   only for local nameservers on the loopback network.  Servers generally
--   enforce a smaller limit.
--
-- >>> maxUdpSize
-- 16384
maxUdpSize :: Word16
maxUdpSize = 16384

-- | Minimum UDP size to advertise. If 'ednsUdpSize' of 'EDNS' is smaller,
--   then this value is sent instead.
--
-- >>> minUdpSize
-- 512
minUdpSize :: Word16
minUdpSize = 512
