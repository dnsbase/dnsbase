{-|
Module      : Net.DNSBase.RData.TLSA
Description : DANE-style key/certificate records (TLSA, SMIMEA, SSHFP, OPENPGPKEY)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

Four DANE-style records that publish cryptographic identifiers
via DNS.  'T_tlsa' (RFC 6698) carries TLS certificate
associations; 'T_smimea' (RFC 8162) carries the same for
S/MIME — both share the wire format of the underlying 'X_tlsa'
representation.  'T_sshfp' (RFC 4255) carries SSH host-key
fingerprints.  'T_openpgpkey' (RFC 7929) carries an OpenPGP
transferable public key.
-}
{-# OPTIONS_GHC -Wno-duplicate-exports #-}
{-# LANGUAGE
    MagicHash
  , RecordWildCards
  , UndecidableInstances
  #-}

module Net.DNSBase.RData.TLSA
    ( -- * TLSA and SMIMEA
      X_tlsa(.., T_TLSA, T_SMIMEA
            , tlsaUsage, tlsaSelector, tlsaMtype, tlsaAssocData
            , smimeaUsage, smimeaSelector, smimeaMtype, smimeaAssocData)
    , type XtlsaConName
      -- *** @T_TLSA@ record pattern synonym fields
    , T_tlsa
    , tlsaUsage, tlsaSelector, tlsaMtype, tlsaAssocData
      -- *** @T_SMIMEA@ record pattern synonym fields
    , T_smimea
    , smimeaUsage, smimeaSelector, smimeaMtype, smimeaAssocData
      -- * SSHFP
    , T_sshfp(..)
      -- * OPENPGPKEY
    , T_openpgpkey(..)
    ) where

import GHC.Exts (proxy#)
import GHC.TypeLits as TL (TypeError, ErrorMessage(..))
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
                       :<>: TL.Text " is not a TLSA or SMIMEA RRTYPE" )

-- | X_tlsa specialised to @TLSA@ records.
--
-- Note that @T_tlsa@ is just a type alias!  The 'T_TLSA' record pattern
-- synonym and its fields are bundled with the underlying 'X_tlsa'
-- data type.  In many cases it is sufficient to import just
-- @X_tlsa(..)@, but if you also need the type alias, it needs to be
-- imported separately:
--
-- > import Net.DNSBase (X_tlsa(..), T_tlsa)
--
type T_tlsa      = X_tlsa N_tlsa

-- | X_tlsa specialised to @SMIMEA@ records.
--
-- Note that @T_smimea@ is just a type alias!  The 'T_SMIMEA' record pattern
-- synonym and its fields are bundled with the underlying 'X_tlsa'
-- data type.  In many cases it is sufficient to import just
-- @X_tlsa(..)@, but if you also need the type alias, it needs to be
-- imported separately:
--
-- > import Net.DNSBase (X_tlsa(..), T_smimea)
--
type T_smimea    = X_tlsa N_smimea

-- | Record pattern synonym viewing the shared 'X_tlsa' record as a
-- @TLSA@ (DANE for TLS) record, RFC 6698.  Fields: 'tlsaUsage',
-- 'tlsaSelector', 'tlsaMtype', 'tlsaAssocData'.  Not coercible to/from
-- 'T_smimea': the role of 'X_tlsa' is /nominal/ because TLSA and SMIMEA
-- bind to different protocols and the shared wire format is
-- coincidental.
pattern T_TLSA :: Word8 -- ^ Certificate Usage
               -> Word8 -- ^ Selector
               -> Word8 -- ^ Matching Type
               -> ShortByteString -- ^ Certificate Association Data
               -> T_tlsa
pattern T_TLSA { tlsaUsage, tlsaSelector, tlsaMtype, tlsaAssocData }
      = (X_TLSA tlsaUsage tlsaSelector tlsaMtype tlsaAssocData :: T_tlsa)
{-# COMPLETE T_TLSA #-}

-- | Record pattern synonym viewing the shared 'X_tlsa' record as an
-- @SMIMEA@ (DANE for S/MIME) record, RFC 8162.  Fields: 'smimeaUsage',
-- 'smimeaSelector', 'smimeaMtype', 'smimeaAssocData'.  Not coercible
-- to/from 'T_tlsa' (see 'T_TLSA' note).
pattern T_SMIMEA :: Word8 -- ^ Certificate Usage
                 -> Word8 -- ^ Selector
                 -> Word8 -- ^ Matching Type
                 -> ShortByteString -- ^ Certificate Association Data
                 -> T_smimea
pattern T_SMIMEA { smimeaUsage, smimeaSelector, smimeaMtype, smimeaAssocData }
      = (X_TLSA smimeaUsage smimeaSelector smimeaMtype smimeaAssocData :: T_smimea)
{-# COMPLETE T_SMIMEA #-}

-- | Shared wire-format representation for DANE certificate-binding
-- records: the @TLSA@ record
-- ([RFC 6698 section 2.1](https://tools.ietf.org/html/rfc6698#section-2.1),
-- DANE for TLS) and the @SMIMEA@ record
-- ([RFC 8162 section 2](https://tools.ietf.org/html/rfc8162#section-2),
-- DANE for S/MIME).
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
-- The type parameter @n@ (either 'N_tlsa' or 'N_smimea')
-- determines the RR type.  Each has its own type synonym
-- ('T_tlsa', 'T_smimea') and matching record pattern synonym
-- ('T_TLSA', 'T_SMIMEA') with the corresponding field-name prefix
-- (@tlsa@, @smimea@).  The role of 'X_tlsa' is /nominal/: the
-- wire format is shared but the two RR types bind to different
-- protocols, so 'T_tlsa' and 'T_smimea' are not coercible.
--
-- Note that @T_tlsa@ and @T_smime@ are just type aliases!  The
-- 'T_TLSA' and 'T_SMIMEA' record pattern synonyms and their
-- fields are bundled with the underlying 'X_tlsa' data type.  In
-- many cases it is sufficient to import just @X_tlsa(..)@, but if
-- you also need the type aliases, they need to be imported
-- separately:
--
-- > import Net.DNSBase (X_tlsa(..), T_tlsa, T_smimea)
--
-- If a received message carries a payload shorter than 3 bytes the
-- record is returned as an opaque RData of the corresponding
-- RRTYPE with the truncated bytes as its value; DANE validators
-- should treat such records as present but "unusable".
--
-- Derived 'Ord' is canonical
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
--
-- See 'T_sshfp' for the SSH host-key fingerprint record and
-- 'T_openpgpkey' for the OpenPGP key record — both also live in
-- this module.
type X_tlsa :: Nat -> Type
type role X_tlsa nominal
data X_tlsa n = X_TLSA
    { x_tlsaUsage     :: Word8           -- ^ Certificate Usage
    , x_tlsaSelector  :: Word8           -- ^ Selector
    , x_tlsaMtype     :: Word8           -- ^ Matching Type
    , x_tlsaAssocData :: ShortByteString -- ^ Certificate Association Data
    }
deriving instance (KnownSymbol (XtlsaConName n)) => Eq (X_tlsa n)
deriving instance (KnownSymbol (XtlsaConName n)) => Ord (X_tlsa n)

instance (Nat16 n, KnownSymbol (XtlsaConName n)) => Show (X_tlsa n) where
    showsPrec p X_TLSA{..} = showsP p $
        showString (symbolVal' (proxy# @(XtlsaConName n))) . showChar ' '
        . shows' x_tlsaUsage    . showChar ' '
        . shows' x_tlsaSelector . showChar ' '
        . shows' x_tlsaMtype    . showChar ' '
        . showAd x_tlsaAssocData
      where
        showAd = shows @Bytes16 . coerce

instance (KnownSymbol (XtlsaConName n)) => Presentable (X_tlsa n) where
    present X_TLSA{..} =
        present     x_tlsaUsage
        . presentSp x_tlsaSelector
        . presentSp x_tlsaMtype
        . presentAd x_tlsaAssocData
      where
        presentAd = presentSp @Bytes16 . coerce

instance (Nat16 n, KnownSymbol (XtlsaConName n)) => KnownRData (X_tlsa n) where
    rdType _ = RRTYPE $ natToWord16 n
    {-# INLINE rdType #-}
    rdEncode X_TLSA{..} = putSizedBuilder $
        mbWord8              x_tlsaUsage
        <> mbWord8           x_tlsaSelector
        <> mbWord8           x_tlsaMtype
        <> mbShortByteString x_tlsaAssocData
    rdDecode _ _ = const do
        x_tlsaUsage     <- get8
        x_tlsaSelector  <- get8
        x_tlsaMtype     <- get8
        x_tlsaAssocData <- getShortByteString
        pure $ RData (X_TLSA{..} :: X_tlsa n)

-- | The @SSHFP@ resource record
-- ([RFC 4255 section 3.1](https://www.rfc-editor.org/rfc/rfc4255.html#section-3.1))
-- — a fingerprint of an SSH host public key.  Three fields: an
-- 8-bit /algorithm/ tag (matches the SSH key algorithm), an 8-bit
-- /fingerprint type/ tag (SHA-1, SHA-256, ...), and the
-- fingerprint bytes.
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
-- See 'X_tlsa' / 'T_openpgpkey' for the other DANE-style records
-- in this module.
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

-- | The @OPENPGPKEY@ resource record
-- ([RFC 7929 section 2.2](https://www.rfc-editor.org/rfc/rfc7929.html#section-2.2))
-- — an OpenPGP transferable public key, carried as raw bytes (no
-- ASCII armor, no base64).  Single-field; presented in
-- base64 form.
--
-- See 'X_tlsa' / 'T_sshfp' for the other DANE-style records in
-- this module.
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
    rdEncode T_OPENPGPKEY{..} = putShortByteString openpgpKey
    rdDecode _ _ = RData . T_OPENPGPKEY <.> getShortNByteString
