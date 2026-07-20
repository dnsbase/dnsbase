-- |
-- Module      : Net.DNSBase.EDNS.Option.EDE
-- Description : Extended DNS Errors (RFC 8914)
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
{-# LANGUAGE OverloadedStrings #-}

module Net.DNSBase.EDNS.Option.EDE
    ( O_ede(..)
    ) where

import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Short as SB
import qualified Data.IntMap.Strict as IM

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.EDNS.Internal.OptNum
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Extensible
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Text
import Net.DNSBase.Internal.Util

-- | [Extended DNS Error](https://www.rfc-editor.org/rfc/rfc8914.html#section-2)
--
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |          INFO-CODE            |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > / EXTRA-TEXT ...                /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- The decoded value carries the wire-format info-code and extra
-- text alongside an /optional/ friendly name ('edeName') looked
-- up from the resolver's EDE name table.  An empty 'edeName'
-- denotes "no entry in the table": the 'Presentable' instance
-- falls back to a bare numeric code in that case.
--
-- The 'Net.DNSBase.EDNS.Option.OptionExtensionVal' for 'O_ede' is the name registry —
-- an 'IM.IntMap' from info-code to user-facing name.
-- Applications can register new names or override standard
-- ones via 'Net.DNSBase.Resolver.extendEdnsOptionWithValue' on
-- 'O_ede', passing the @(code, name)@ pair to add.
data O_ede = O_EDE
    { edeInfoCode :: !Word16
        -- ^ EDE info-code (RFC 8914, section 4).
    , edeName     :: !ShortByteString
        -- ^ Friendly name looked up at decode time, or 'mempty'
        --   when the table has no matching entry.
    , edeText     :: !ShortByteString
        -- ^ Extra-text payload (UTF-8).  May be empty.
    } deriving (Eq, Show)

-- | Presentation form modelled after BIND @dig@:
--
-- > 9 (DNSKEY Missing): "no SEP matching the DS found for dnssec-failed.org."
--
-- The numeric code is always shown.  The friendly name (parenthesised,
-- raw — registry tags don't need quoting) and trailing colon+text
-- (DNS text quoting applied — the EXTRA-TEXT is free-form payload)
-- appear when present; an unregistered code with no extra text
-- renders as just the bare number.
instance Presentable O_ede where
    present (O_EDE code name text) =
        present code . namePart . textPart
      where
        namePart
            | SB.null name = id
            | otherwise    = present @String " ("
                           . (B.shortByteString name <>)
                           . present @String ")"
        textPart
            | SB.null text = id
            | otherwise    = present @String ": "
                           . coerce (present @DnsText) text

instance KnownEdnsOption O_ede where
    type OptionExtensionVal O_ede = IM.IntMap ShortByteString
    optionExtensionVal _ = baseEdeNames

    optNum _ = EDE
    {-# INLINE optNum #-}
    optEncode (O_EDE c _ t) = do
        put16 c
        putShortByteString t
    optDecode _ namesMap len = do
        code <- get16
        text <- getShortNByteString (len - 2)
        pure $! EdnsOption $! O_EDE code
            (IM.findWithDefault mempty (fromIntegral code) namesMap)
            text

instance ValueExtensible O_ede (IM.IntMap ShortByteString) where
    -- A caller registers a @(code, name)@ pair; later
    -- registrations win over earlier entries at the same code.
    type ValueExtensionArg O_ede b = (b ~ (Word16, ShortByteString))
    extendByValue _ (code, name) m = IM.insert (fromIntegral code) name m

-- | Built-in friendly names for the EDE info-codes registered by
-- [IANA](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes)
-- through RFC 8914 section 4 and subsequent assignments.
-- Applications can extend or override this map via
-- 'Net.DNSBase.Resolver.extendEdnsOptionWithValue' on 'O_ede'.
baseEdeNames :: IM.IntMap ShortByteString
baseEdeNames = IM.fromList
    [ ( 0, "Other Error")
    , ( 1, "Unsupported DNSKEY Algorithm")
    , ( 2, "Unsupported DS Digest Type")
    , ( 3, "Stale Answer")
    , ( 4, "Forged Answer")
    , ( 5, "DNSSEC Indeterminate")
    , ( 6, "DNSSEC Bogus")
    , ( 7, "Signature Expired")
    , ( 8, "Signature Not Yet Valid")
    , ( 9, "DNSKEY Missing")
    , (10, "RRSIGs Missing")
    , (11, "No Zone Key Bit Set")
    , (12, "NSEC Missing")
    , (13, "Cached Error")
    , (14, "Not Ready")
    , (15, "Blocked")
    , (16, "Censored")
    , (17, "Filtered")
    , (18, "Prohibited")
    , (19, "Stale NXDOMAIN Answer")
    , (20, "Not Authoritative")
    , (21, "Not Supported")
    , (22, "No Reachable Authority")
    , (23, "Network Error")
    , (24, "Invalid Data")
    , (25, "Signature Expired before Valid")
    , (26, "Too Early")
    , (27, "Unsupported NSEC3 Iterations Value")
    , (28, "Unable to conform to policy")
    , (29, "Synthesized")
    , (30, "Invalid Query Type")
    , (31, "Rate Limited")
    , (32, "Over Quota")
    , (33, "Negative Trust Anchor")
    , (34, "New Delegation Only")
    ]
