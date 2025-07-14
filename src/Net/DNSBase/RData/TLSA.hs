{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.RData.TLSA
    ( T_tlsa(..)
    , T_sshfp(..)
    ) where

import Net.DNSBase.Internal.Util

import Net.DNSBase.Bytes
import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE

-- | [TLSA RDATA](https://tools.ietf.org/html/rfc6698#section-2.1).
-- DANE TLSA record binding certificate data to a protocol endpoint.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |  Cert. Usage  |   Selector    | Matching Type |               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
-- > /                                                               /
-- > /                 Certificate Association Data                  /
-- > /                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- Note: If the received message contains a truncated value with a payload that
-- is shorter than 3 bytes, the record will instead will be returned as an
-- 'Opaque' with an RRTYPE of TLSA, and the truncated data as its value.  DANE
-- validators should treat such records as present, but "unusable".
--
-- Ordered canonically:
-- [RFC4034](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)
--
data T_tlsa = T_TLSA
    { tlsaUsage     :: Word8
    , tlsaSelector  :: Word8
    , tlsaMtype     :: Word8
    , tlsaAssocData :: ShortByteString
    } deriving (Eq, Ord)

instance Show T_tlsa where
    showsPrec p T_TLSA{..} = showsP p $
        showString "T_TLSA"   . showChar ' '
        . shows' tlsaUsage    . showChar ' '
        . shows' tlsaSelector . showChar ' '
        . shows' tlsaMtype    . showChar ' '
        . showAd tlsaAssocData
      where
        showAd = shows @Bytes16 . coerce

instance Presentable T_tlsa where
    present T_TLSA{..} =
        present     tlsaUsage
        . presentSp tlsaSelector
        . presentSp tlsaMtype
        . presentAd tlsaAssocData
      where
        presentAd = presentSp @Bytes16 . coerce

instance KnownRData T_tlsa where
    rdType _ = TLSA
    {-# INLINE rdType #-}
    rdEncode T_TLSA{..} = putSizedBuilder $
        mbWord8              tlsaUsage
        <> mbWord8           tlsaSelector
        <> mbWord8           tlsaMtype
        <> mbShortByteString tlsaAssocData
    rdDecode _ _ len = do
        tlsaUsage     <- get8
        tlsaSelector  <- get8
        tlsaMtype     <- get8
        tlsaAssocData <- getShortNByteString (len - 3)
        return $ RData T_TLSA{..}

-- | [SSHFP RDATA](https://www.rfc-editor.org/rfc/rfc4255.html#section-3.1)
-- Stores a fingerprint of an SSH public host key.
--
-- >                     1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- > 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |   algorithm   |    fp type    |                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               /
-- > /                                                               /
-- > /                          fingerprint                          /
-- > /                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
data T_sshfp = T_SSHFP
    { sshfpKeyAlgor :: Word8
    , sshfpHashType :: Word8
    , sshfpKeyValue :: ShortByteString
    } deriving (Eq, Ord)

instance Show T_sshfp where
    showsPrec p T_SSHFP{..} = showsP p $
        showString "T_SSHFP "
        . shows' sshfpKeyAlgor . showChar ' '
        . shows' sshfpHashType . showChar ' '
        . showKv sshfpKeyValue
      where
        showKv = shows @Bytes16 . coerce

instance Presentable T_sshfp where
    present T_SSHFP{..} =
        present     sshfpKeyAlgor
        . presentSp sshfpHashType
        . presentKv sshfpKeyValue
      where
        presentKv = presentSp @Bytes16 . coerce

instance KnownRData T_sshfp where
    rdType _ = SSHFP
    {-# INLINE rdType #-}
    rdEncode T_SSHFP{..} = putSizedBuilder $
        mbWord8              sshfpKeyAlgor
        <> mbWord8           sshfpHashType
        <> mbShortByteString sshfpKeyValue
    rdDecode _ _ len = do
        sshfpKeyAlgor <- get8
        sshfpHashType <- get8
        sshfpKeyValue <- getShortNByteString (len - 2)
        return $ RData T_SSHFP{..}
