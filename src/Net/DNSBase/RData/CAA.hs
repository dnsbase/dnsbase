{-|
Module      : Net.DNSBase.RData.CAA
Description : Certification Authority Authorization (CAA)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable
-}
{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.RData.CAA
    ( -- * Certification Authority Authorisation
      T_caa(..)
    , validCaaTag
    ) where

import qualified Data.ByteString.Short as SB

import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE
import Net.DNSBase.Text

-- | The @CAA@ resource record
-- ([RFC 8659 section 4.1](https://www.rfc-editor.org/rfc/rfc8659.html#section-4.1))
-- — three fields: an 8-bit flag byte, an ASCII-alphanumeric property
-- /tag/ (1..255 bytes), and the property's value (free-form bytes).
--
-- Tags are compared case-sensitively when comparing 'T_caa'
-- 'RData' objects.  CAs are required by RFC 8659 to handle tags
-- case-insensitively; that's a check for application-layer code,
-- not for the wire-format codec.  Use 'validCaaTag' to verify a
-- tag's syntactic constraints before encoding.
--
-- The 'Ord' instance compares the flag byte, then tag length,
-- then tag bytes, then value bytes — wire-encoding order, so it
-- agrees with the canonical RR-content ordering of
-- [RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
data T_caa = T_CAA
    { caaFlags :: Word8
    , caaTag   :: ShortByteString
    , caaValue :: ShortByteString }
    deriving (Eq, Show)

instance Ord T_caa where
    a `compare` b = caaFlags  a `compare` caaFlags  b
                 <> tagLength a `compare` tagLength b
                 <> caaTag    a `compare` caaTag    b
                 <> caaValue  a `compare` caaValue  b
      where
        tagLength = SB.length . caaTag

instance Presentable T_caa where
    present T_CAA{..}
        = present caaFlags
          . presentSp caaTag
          . presentSp @DnsText (coerce caaValue)

instance KnownRData T_caa where
    rdType _ = CAA
    rdEncode T_CAA{..}
        | validCaaTag caaTag = putSizedBuilder $
                                   mbWord8 caaFlags
                                <> mbShortByteStringLen8 caaTag
                                <> mbShortByteString caaValue
        | otherwise         = failWith CantEncode
    rdDecode _ _ = const do
        caaFlags <- get8
        caaTag   <- getShortByteStringLen8
        when (not $ validCaaTag caaTag) $ failSGet "CAA tag not alphanumeric"
        caaValue <- getShortByteString
        pure $ RData T_CAA{..}

-- | Verify a CAA tag's syntactic constraints: non-empty and made
-- entirely of ASCII alphanumeric bytes (RFC 8659 section 4.2).  Required
-- before encoding; the decoder applies the same check and rejects
-- a wire-form 'T_caa' whose tag fails it.
validCaaTag :: ShortByteString -> Bool
validCaaTag = (&&) <$> not . SB.null <*> SB.all isalnum
  where
    isalnum w = w - 0x30 < 10 || (w .&. 0xdf) - 0x41 < 26
