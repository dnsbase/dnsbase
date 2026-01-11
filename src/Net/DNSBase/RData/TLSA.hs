{-# LANGUAGE
    MagicHash
  , RecordWildCards
  , UndecidableInstances
  #-}

module Net.DNSBase.RData.TLSA
    ( X_tlsa(.., T_TLSA, T_SMIMEA), T_tlsa, T_smimea
    , T_sshfp(..)
    , T_openpgpkey(..)
    ) where

import GHC.Exts (proxy#)
import GHC.TypeLits (TypeError, ErrorMessage(..))
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal')

import Net.DNSBase.Internal.Util

import Net.DNSBase.Bytes
import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Nat16
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE

type XtlsaConName :: Nat -> Symbol
type family XtlsaConName n where
    XtlsaConName N_tlsa   = "T_TLSA"
    XtlsaConName N_smimea = "T_SMIMEA"
    XtlsaConName n        = TypeError
                     ( ShowType n
                       :<>: Text " is not a TLSA or SMIMEA RRTYPE" )

-- | @TLSA@ and @SMIMEA@ RData are structurally identical.
type T_tlsa      = X_tlsa N_tlsa
type T_smimea    = X_tlsa N_smimea

-- | Interpret an 'X_tlsa' structure of type @TLSA@ as a 'T_tlsa'.
{-# COMPLETE T_TLSA #-}
pattern  T_TLSA :: Word8 -> Word8 -> Word8 -> ShortByteString -> T_tlsa
pattern  T_TLSA u s m d = (X_TLSA u s m d :: T_tlsa)
-- | Interpret an 'X_tlsa' structure of type @SMIMEA@ as a 'T_smimea'.
{-# COMPLETE T_SMIMEA #-}
pattern T_SMIMEA :: Word8 -> Word8 -> Word8 -> ShortByteString -> T_smimea
pattern T_SMIMEA u s m d = (X_TLSA u s m d :: T_smimea)

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
type X_tlsa :: Nat -> Type
data X_tlsa n = X_TLSA
    { tlsaUsage     :: Word8
    , tlsaSelector  :: Word8
    , tlsaMtype     :: Word8
    , tlsaAssocData :: ShortByteString
    }
deriving instance (KnownSymbol (XtlsaConName n)) => Eq (X_tlsa n)
deriving instance (KnownSymbol (XtlsaConName n)) => Ord (X_tlsa n)

instance (Nat16 n, KnownSymbol (XtlsaConName n)) => Show (X_tlsa n) where
    showsPrec p X_TLSA{..} = showsP p $
        showString (symbolVal' (proxy# @(XtlsaConName n))) . showChar ' '
        . shows' tlsaUsage    . showChar ' '
        . shows' tlsaSelector . showChar ' '
        . shows' tlsaMtype    . showChar ' '
        . showAd tlsaAssocData
      where
        showAd = shows @Bytes16 . coerce

instance (KnownSymbol (XtlsaConName n)) => Presentable (X_tlsa n) where
    present X_TLSA{..} =
        present     tlsaUsage
        . presentSp tlsaSelector
        . presentSp tlsaMtype
        . presentAd tlsaAssocData
      where
        presentAd = presentSp @Bytes16 . coerce

instance (Nat16 n, KnownSymbol (XtlsaConName n)) => KnownRData (X_tlsa n) where
    rdType _ = RRTYPE $ natToWord16 n
    {-# INLINE rdType #-}
    rdEncode X_TLSA{..} = putSizedBuilder $
        mbWord8              tlsaUsage
        <> mbWord8           tlsaSelector
        <> mbWord8           tlsaMtype
        <> mbShortByteString tlsaAssocData
    rdDecode _ _ = const do
        tlsaUsage     <- get8
        tlsaSelector  <- get8
        tlsaMtype     <- get8
        tlsaAssocData <- getShortByteString
        pure $ RData (X_TLSA{..} :: X_tlsa n)

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
    rdDecode _ _ = const do
        sshfpKeyAlgor <- get8
        sshfpHashType <- get8
        sshfpKeyValue <- getShortByteString
        return $ RData T_SSHFP{..}

-- | [OPENPGPKEY RDATA](https://www.rfc-editor.org/rfc/rfc7929.html#section-2.2)
-- OpenPGP Transferable Public Key, without ASCII armor or base64 encoding.
--
data T_openpgpkey = T_OPENPGPKEY
    { openpgpKey :: ShortByteString
    } deriving (Eq, Ord)

instance Show T_openpgpkey where
    showsPrec p T_OPENPGPKEY{..} = showsP p $
        showString "T_OPENPGPKEY " . shows @Bytes64 (coerce openpgpKey)

instance Presentable T_openpgpkey where
    present T_OPENPGPKEY{..} = present @Bytes64 (coerce openpgpKey)

instance KnownRData T_openpgpkey where
    rdType _ = OPENPGPKEY
    {-# INLINE rdType #-}
    rdEncode T_OPENPGPKEY{..} = putSizedBuilder $
        mbShortByteString openpgpKey
    rdDecode _ _ = RData . T_OPENPGPKEY <.> getShortNByteString
