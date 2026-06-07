{-|
Module      : Net.DNSBase.RData.Dnssec
Description : DNSSEC chain-of-trust records (DS, DNSKEY, RRSIG, plus IPSECKEY and ZONEMD)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The DNSSEC chain-of-trust RR types from RFC 4034 — 'T_ds',
'T_dnskey', 'T_rrsig' — plus their parent\/child mirror
announcements: 'T_cds' and 'T_cdnskey' (RFC 7344) carry the
child-side signalling of which DS and DNSKEY records the parent
should publish.  The legacy 'T_key' and 'T_sig' records, still
used by SIG(0) transaction authentication (RFC 2535, RFC 2931),
share a codec with their DNSSEC successors.

The three groups DS\/CDS, DNSKEY\/CDNSKEY\/KEY, and SIG\/RRSIG
each have a single underlying data type ('X_ds', 'X_key',
'X_sig') with the RR type carried at the type level.  DS and
KEY have the @phantom@ type role on @n@, so values are
mutually coercible; the SIG family has @nominal@, since SIG(0)
signs a single transaction while RRSIG signs an RRSet, and
conflating them at the type level would be unsafe.

'T_ipseckey' (RFC 4025) and 'T_zonemd' (RFC 8976) live here
too, alongside the re-export of "Net.DNSBase.RData.NSEC" for
the denial-of-existence records.
-}
{-# OPTIONS_GHC -Wno-duplicate-exports #-}
{-# LANGUAGE
    MagicHash
  , RecordWildCards
  , UndecidableInstances
  #-}
module Net.DNSBase.RData.Dnssec
    ( -- * DS, DNSKEY and RRSIG
      -- ** DS resource records
      X_ds(.., T_DS, T_CDS
          , dsKtag, dsKalg, dsHalg, dsHval
          , cdsKtag, cdsKalg, cdsHalg, cdsHval)
    , type XdsConName
      -- **** @T_DS@ record pattern synonym fields
    , T_ds
    , dsKtag, dsKalg, dsHalg, dsHval
      -- **** @T_CDS@ record pattern synonym fields
    , T_cds
    , cdsKtag, cdsKalg, cdsHalg, cdsHval
      -- ** DNSKEY resource records
    , X_key(.., T_DNSKEY, T_CDNSKEY, T_KEY
           , dnskeyFlags, dnskeyProto, dnskeyAlgor, dnskeyValue
           , cdnskeyFlags, cdnskeyProto, cdnskeyAlgor, cdnskeyValue
           , keyFlags, keyProto, keyAlgor, keyValue)
    , type XkeyConName
      -- *** @DNSKEY@ record pattern synonym fields
    , T_dnskey
    , dnskeyFlags, dnskeyProto, dnskeyAlgor, dnskeyValue
      -- **** Compute a DNSKey tag
    , keytag
      -- *** @CDNSKEY@ record pattern synonym fields
    , T_cdnskey
    , cdnskeyFlags, cdnskeyProto, cdnskeyAlgor, cdnskeyValue
      -- *** @KEY@ record pattern synonym fields
    , T_key
    , keyFlags, keyProto, keyAlgor, keyValue
      -- ** RRSIG resource records
    , X_sig(.., T_RRSIG, T_SIG
           , rrsigType, rrsigKeyAlg, rrsigNumLabels, rrsigTTL
           , rrsigExpiration, rrsigInception, rrsigKeyTag, rrsigZone, rrsigValue
           , sigType, sigKeyAlg, sigNumLabels, sigTTL
           , sigExpiration, sigInception, sigKeyTag, sigZone, sigValue)
    , type XsigConName
      -- *** @RRSIG@ record pattern synonym fields
    , T_rrsig
    , rrsigType, rrsigKeyAlg, rrsigNumLabels, rrsigTTL
    , rrsigExpiration, rrsigInception, rrsigKeyTag, rrsigZone, rrsigValue
      -- *** @SIG@ record pattern synonym fields
    , T_sig
    , sigType, sigKeyAlg, sigNumLabels, sigTTL
    , sigExpiration, sigInception, sigKeyTag, sigZone, sigValue
      -- * IPSECKEY resource records
    , T_ipseckey(IPSecKey), IPSecKeyGateway(..)
      -- * Zone digest
    , T_zonemd(..)
    , module Net.DNSBase.RData.NSEC
    ) where

import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Short as SB
import GHC.Exts (proxy#)
import GHC.TypeLits as TL (TypeError, ErrorMessage(..))
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal')

import Net.DNSBase.Internal.Util

import Net.DNSBase.Bytes
import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Nat16
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RData.NSEC
import Net.DNSBase.RRTYPE
import Net.DNSBase.Secalgs

type XdsConName :: Nat -> Symbol
type family XdsConName n where
    XdsConName N_ds  = "T_DS"
    XdsConName N_cds = "T_CDS"
    XdsConName n     = TypeError
                     ( ShowType n
                       :<>: TL.Text " is not a DS or CDS RRTYPE" )

type XkeyConName :: Nat -> Symbol
type family XkeyConName n where
    XkeyConName N_dnskey  = "T_DNSKEY"
    XkeyConName N_cdnskey = "T_CDNSKEY"
    XkeyConName N_key     = "T_KEY"
    XkeyConName n         = TypeError
                            ( ShowType n
                              :<>: TL.Text " is not a DNSSEC key RRTYPE" )

type XsigConName :: Nat -> Symbol
type family XsigConName n where
    XsigConName N_rrsig  = "T_RRSIG"
    XsigConName N_sig    = "T_SIG"
    XsigConName n        = TypeError
                           ( ShowType n
                             :<>: TL.Text " is not a SIG or RRSIG RRTYPE" )

-- | X_ds specialised to @DS@ records.
--
-- Note that @T_ds@ is just a type alias!  The 'T_DS' record pattern
-- synonym and its fields are bundled with the underlying 'X_ds'
-- data type.  In many cases it is sufficient to import just
-- @X_ds(..)@, but if you also need the type alias, it needs to be
-- imported separately:
--
-- > import Net.DNSBase (X_ds(..), T_ds)
--
type T_ds      = X_ds N_ds

-- | X_ds specialised to @CDS@ records.
--
-- Note that @T_cds@ is just a type alias!  The 'T_CDS' record pattern
-- synonym and its fields are bundled with the underlying 'X_ds'
-- data type.  In many cases it is sufficient to import just
-- @X_ds(..)@, but if you also need the type alias it needs to be
-- imported separately:
--
-- > import Net.DNSBase (X_ds(..), T_cds)
--
type T_cds     = X_ds N_cds

-- | Record pattern synonym viewing the shared 'X_ds' record as a
-- parent-side @DS@ record (RFC 4034, section 5).  Fields: 'dsKtag',
-- 'dsKalg', 'dsHalg', 'dsHval'.  Coercible to/from 'T_CDS'.
pattern T_DS :: Word16 -- ^ Key Tag
             -> DNSKEYAlg -- ^ Algorithm
             -> DSHashAlg -- ^ Digest-algorithm /selector/ (a 'DSHashAlg' code), distinct from the digest bytes below
             -> ShortByteString -- ^ Digest
             -> T_ds
pattern T_DS { dsKtag, dsKalg, dsHalg, dsHval }
      = (X_DS dsKtag dsKalg dsHalg dsHval :: T_ds)
{-# COMPLETE T_DS #-}

-- | Record pattern synonym viewing the shared 'X_ds' record as a
-- child-side @CDS@ announcement (RFC 7344).  Fields: 'cdsKtag',
-- 'cdsKalg', 'cdsHalg', 'cdsHval'.  Coercible to/from 'T_DS'.
pattern T_CDS :: Word16 -- ^ Key Tag
              -> DNSKEYAlg -- ^ Algorithm
              -> DSHashAlg -- ^ Digest-algorithm /selector/ (a 'DSHashAlg' code), distinct from the digest bytes below
              -> ShortByteString -- ^ Digest
              -> T_cds
pattern T_CDS { cdsKtag, cdsKalg, cdsHalg, cdsHval }
      = (X_DS cdsKtag cdsKalg cdsHalg cdsHval :: T_cds)
{-# COMPLETE T_CDS #-}

-- | X_key specialised to @DNSKEY@ records.
--
-- Note that @T_dnskey@ is just a type alias!  The 'T_DNSKEY'
-- record pattern synonym and its fields are bundled with the
-- underlying 'X_key' data type.  In many cases it is sufficient
-- to import just @X_key(..)@, but if you also need the type
-- alias, it needs to be imported separately:
--
-- > import Net.DNSBase (X_key(..), T_dnskey)
--
type T_dnskey  = X_key N_dnskey

-- | X_key specialised to @CDNSKEY@ records.
--
-- Note that @T_cdnskey@ is just a type alias!  The 'T_CDNSKEY'
-- record pattern synonym and its fields are bundled with the
-- underlying 'X_key' data type.  In many cases it is sufficient
-- to import just @X_key(..)@, but if you also need the type
-- alias, it needs to be imported separately:
--
-- > import Net.DNSBase (X_key(..), T_cdnskey)
--
type T_cdnskey = X_key N_cdnskey

-- | X_key specialised to @KEY@ records.
--
-- Note that @T_key@ is just a type alias!  The 'T_KEY' record
-- pattern synonym and its fields are bundled with the underlying
-- 'X_key' data type.  In many cases it is sufficient to import
-- just @X_key(..)@, but if you also need the type alias, it needs
-- to be imported separately:
--
-- > import Net.DNSBase (X_key(..), T_key)
--
type T_key     = X_key N_key

-- | Record pattern synonym viewing the shared 'X_key' record as a
-- DNSSEC @DNSKEY@ (RFC 4034, section 2).  Fields: 'dnskeyFlags',
-- 'dnskeyProto', 'dnskeyAlgor', 'dnskeyValue'.  Coercible to/from
-- 'T_cdnskey'; CDNSKEY is the child-side announcement of which DNSKEY
-- KSKs the parent should reference as sources for future DS records.
pattern T_DNSKEY :: Word16 -- ^ Flags
                 -> Word8 -- ^ Protocol selector; MUST be 3 for DNSKEY (RFC 4034 section 2.1.2)
                 -> DNSKEYAlg -- ^ Algorithm
                 -> ShortByteString -- ^ Public Key
                 -> T_dnskey
pattern T_DNSKEY { dnskeyFlags, dnskeyProto, dnskeyAlgor, dnskeyValue }
      = (X_KEY dnskeyFlags dnskeyProto dnskeyAlgor dnskeyValue :: T_dnskey)
{-# COMPLETE T_DNSKEY #-}

-- | Record pattern synonym viewing the shared 'X_key' record as a
-- child-side @CDNSKEY@ announcement (RFC 7344).  Fields:
-- 'cdnskeyFlags', 'cdnskeyProto', 'cdnskeyAlgor', 'cdnskeyValue'.
-- Coercible to/from 'T_dnskey'.
pattern T_CDNSKEY :: Word16 -- ^ Flags
                  -> Word8 -- ^ Protocol selector; MUST be 3 for CDNSKEY (RFC 4034 section 2.1.2, via RFC 7344)
                  -> DNSKEYAlg -- ^ Algorithm
                  -> ShortByteString -- ^ Public Key
                  -> T_cdnskey
pattern T_CDNSKEY { cdnskeyFlags, cdnskeyProto, cdnskeyAlgor, cdnskeyValue }
      = (X_KEY cdnskeyFlags cdnskeyProto cdnskeyAlgor cdnskeyValue :: T_cdnskey)
{-# COMPLETE T_CDNSKEY #-}

-- | Record pattern synonym viewing the shared 'X_key' record as a
-- legacy @KEY@ record (RFC 2535, section 3), still used by SIG(0)
-- transaction authentication.  Fields: 'keyFlags', 'keyProto',
-- 'keyAlgor', 'keyValue'.  Coercible to/from 'T_dnskey' and
-- 'T_cdnskey'.
pattern T_KEY :: Word16 -- ^ Flags
              -> Word8 -- ^ Protocol selector;
                       -- for DNSKEY the only valid value is 3
                       -- (RFC 4034 section 2.1.2), other values
                       -- appear in legacy KEY records
              -> DNSKEYAlg -- ^ Algorithm
              -> ShortByteString -- ^ Public Key
              -> T_key
pattern T_KEY { keyFlags, keyProto, keyAlgor, keyValue }
      = (X_KEY keyFlags keyProto keyAlgor keyValue :: T_key)
{-# COMPLETE T_KEY #-}

-- | X_sig specialised to @RRSIG@ records.
--
-- Note that @T_rrsig@ is just a type alias!  The 'T_RRSIG' record
-- pattern synonym and its fields are bundled with the underlying
-- 'X_sig' data type.  In many cases it is sufficient to import
-- just @X_sig(..)@, but if you also need the type alias, it needs
-- to be imported separately:
--
-- > import Net.DNSBase (X_sig(..), T_rrsig)
--
type T_rrsig = X_sig N_rrsig

-- | X_sig specialised to @SIG@ / @SIG(0)@ records.
--
-- Note that @T_sig@ is just a type alias!  The 'T_SIG' record
-- pattern synonym and its fields are bundled with the underlying
-- 'X_sig' data type.  In many cases it is sufficient to import
-- just @X_sig(..)@, but if you also need the type alias, it needs
-- to be imported separately:
--
-- > import Net.DNSBase (X_sig(..), T_sig)
--
type T_sig   = X_sig N_sig

-- | Record pattern synonym viewing the shared 'X_sig' record as a
-- DNSSEC @RRSIG@ (RFC 4034, section 3).  Fields: 'rrsigType',
-- 'rrsigKeyAlg', 'rrsigNumLabels', 'rrsigTTL', 'rrsigExpiration',
-- 'rrsigInception', 'rrsigKeyTag', 'rrsigZone', 'rrsigValue'.
-- 'Eq' and 'Ord' compare the signer name in canonical wire form
-- (via 'equalWireHost' / 'compareWireHost'); canonical RR
-- ordering does not meaningfully apply to RRSIG (see 'X_sig').
pattern T_RRSIG :: RRTYPE -- ^ Type Covered
                -> DNSKEYAlg -- ^ Algorithm
                -> Word8 -- ^ Number of labels in the signed owner name, excluding any leading wildcard ('*') and the trailing root (RFC 4034 section 3.1.3)
                -> Word32 -- ^ Original TTL
                -> Int64 -- ^ Signature expiration as absolute 'Int64' time; 32-bit serial-number arithmetic on the wire (see 'X_sig' for the conversion)
                -> Int64 -- ^ Signature inception as absolute 'Int64' time; same serial-number caveat as 'rrsigExpiration'
                -> Word16 -- ^ Key Tag
                -> Domain -- ^ Signer's Name
                -> ShortByteString -- ^ Signature
                -> T_rrsig
pattern T_RRSIG
    { rrsigType, rrsigKeyAlg, rrsigNumLabels, rrsigTTL
    , rrsigExpiration, rrsigInception, rrsigKeyTag, rrsigZone, rrsigValue
    } = ( X_SIG rrsigType rrsigKeyAlg rrsigNumLabels rrsigTTL
                rrsigExpiration rrsigInception rrsigKeyTag rrsigZone rrsigValue
        :: T_rrsig )
{-# COMPLETE T_RRSIG #-}

-- | Record pattern synonym viewing the shared 'X_sig' record as a
-- legacy @SIG@ record (RFC 2535, section 4.1) or @SIG(0)@
-- transaction authenticator (RFC 2931).  Fields: 'sigType',
-- 'sigKeyAlg', 'sigNumLabels', 'sigTTL', 'sigExpiration',
-- 'sigInception', 'sigKeyTag', 'sigZone', 'sigValue'.  'Eq' and
-- 'Ord' compare the signer name in canonical wire form
-- (via 'equalWireHost' / 'compareWireHost'); see 'X_sig' for why
-- 'T_sig' and 'T_rrsig' are not coercible.
pattern T_SIG :: RRTYPE -- ^ Type Covered
              -> DNSKEYAlg -- ^ Algorithm
              -> Word8 -- ^ Number of labels in the signed owner name, excluding any leading wildcard ('*') and the trailing root (RFC 4034 section 3.1.3)
              -> Word32 -- ^ Original TTL
              -> Int64 -- ^ Signature expiration as absolute 'Int64' time; 32-bit serial-number arithmetic on the wire (see 'X_sig' for the conversion)
              -> Int64 -- ^ Signature inception as absolute 'Int64' time; same serial-number caveat as 'sigExpiration'
              -> Word16 -- ^ Key Tag
              -> Domain -- ^ Signer's Name
              -> ShortByteString -- ^ Signature
              -> T_sig
pattern T_SIG
    { sigType, sigKeyAlg, sigNumLabels, sigTTL
    , sigExpiration, sigInception, sigKeyTag, sigZone, sigValue
    } = ( X_SIG sigType sigKeyAlg sigNumLabels sigTTL
                sigExpiration sigInception sigKeyTag sigZone sigValue
        :: T_sig )
{-# COMPLETE T_SIG #-}

-------------------
-- RData structure Definitions

-- | Shared wire-format representation for DNSSEC delegation-signer
-- records: the parent-side @DS@ record
-- ([RFC 4034 section 5.1](https://datatracker.ietf.org/doc/html/rfc4034#section-5.1))
-- and the child-side @CDS@ announcement
-- ([RFC 7344 section 3.1](https://www.rfc-editor.org/rfc/rfc7344.html#section-3.1)).
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |           Key Tag             |  Algorithm    |  Digest Type  |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > /                                                               /
-- > /                            Digest                             /
-- > /                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- The type parameter @n@ (either 'N_ds' or 'N_cds') determines
-- the RR type.  Each has its own type synonym ('T_ds', 'T_cds')
-- and matching record pattern synonym ('T_DS', 'T_CDS') with the
-- corresponding field-name prefix (@ds@, @cds@).
--
-- The wire format is identical and the type role of @n@ is
-- @phantom@, so 'T_ds' and 'T_cds' are mutually coercible —
-- useful for promoting a child-side CDS announcement into a
-- parent-side DS without rebuilding the value.
--
-- Note that @T_ds@ and @T_cds@ are just type aliases!  The 'T_DS'
-- and 'T_CDS' record pattern synonyms and their fields are
-- bundled with the underlying 'X_ds' data type.  In many cases it
-- is sufficient to import just @X_ds(..)@, but if you also need
-- the type aliases, they need to be imported separately:
--
-- > import Net.DNSBase (X_ds(..), T_ds, T_cds)
--
-- No embedded domain field, so derived 'Ord' agrees with the
-- canonical wire-form octet ordering
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
--
-- The record pattern synonyms 'T_DS' and 'T_CDS' build the
-- corresponding 'T_ds' or 'T_cds' value directly, with their own
-- field-name prefixes (@ds@ and @cds@):
--
-- > :set -XOverloadedStrings
-- > let ds  = T_DS  { dsKtag  = 12345
-- >                 , dsKalg  = 13
-- >                 , dsHalg  = 2
-- >                 , dsHval  = coerce @Bytes16 "0001...1e1f" }
-- >     cds = T_CDS { cdsKtag = 12345
-- >                 , cdsKalg = 13
-- >                 , cdsHalg = 2
-- >                 , cdsHval = coerce @Bytes16 "0001...1e1f" }
-- >  in RData ds : RData cds : []
--
-- Functions that work on either RR type can use the
-- underscore-prefixed selectors on the shared 'X_ds' record:
--
-- > hashTypeVal :: forall n. X_ds n -> (Word8, ShortByteString)
-- > hashTypeVal = (,) <$> x_dsHalg <*> x_dsHval
--
type X_ds :: Nat -> Type
data X_ds n = X_DS
    { x_dsKtag :: Word16 -- ^ Key Tag
    , x_dsKalg :: DNSKEYAlg -- ^ Algorithm
    , x_dsHalg :: DSHashAlg -- ^ Digest Type
    , x_dsHval :: ShortByteString -- ^ Digest
    }
deriving instance (KnownSymbol (XdsConName n)) => Eq (X_ds n)
deriving instance (KnownSymbol (XdsConName n)) => Ord (X_ds n)

instance (Nat16 n, KnownSymbol (XdsConName n)) => Show (X_ds n) where
    showsPrec p X_DS{..} = showsP p $
        showString (symbolVal' (proxy# @(XdsConName n))) . showChar ' '
        . shows' x_dsKtag     . showChar ' '
        . shows' x_dsKalg     . showChar ' '
        . shows' x_dsHalg     . showChar ' '
        . showHv x_dsHval
      where
        showHv = shows @Bytes16 . coerce

instance (KnownSymbol (XdsConName n)) => Presentable (X_ds n) where
    present X_DS{..} =
        present     x_dsKtag
        . presentSp x_dsKalg
        . presentSp x_dsHalg
        . presentHv x_dsHval
      where
        presentHv = presentSp @Bytes16 . coerce

instance (Nat16 n, KnownSymbol (XdsConName n)) => KnownRData (X_ds n) where
    rdType _ = RRTYPE $ natToWord16 n
    {-# INLINE rdType #-}
    rdEncode X_DS{..} = putSizedBuilder $!
           mbWord16       x_dsKtag
        <> coerce mbWord8 x_dsKalg
        <> coerce mbWord8 x_dsHalg
        <> mbShortByteString x_dsHval
    rdDecode _ _ = const do
        x_dsKtag <- get16
        x_dsKalg <- DNSKEYAlg <$> get8
        x_dsHalg <- DSHashAlg <$> get8
        x_dsHval <- getShortByteString
        pure $ RData (X_DS{..} :: X_ds n)

-- | Shared wire-format representation for DNSSEC signing-key
-- records: the @DNSKEY@ record
-- ([RFC 4034 section 2](https://datatracker.ietf.org/doc/html/rfc4034#section-2))
-- published at the child zone apex, the @CDNSKEY@ child-side
-- announcement
-- ([RFC 7344 section 3.2](https://www.rfc-editor.org/rfc/rfc7344.html#section-3.2))
-- of which KSKs the parent should reference, and the legacy
-- @KEY@ record
-- ([RFC 2535 section 3.1](https://datatracker.ietf.org/doc/html/rfc2535#section-3.1))
-- still used by SIG(0) transaction authentication and otherwise
-- effectively unused in modern deployments.
--
-- >                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >  |              Flags            |    Protocol   |   Algorithm   |
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >  /                                                               /
-- >  /                            Public Key                         /
-- >  /                                                               /
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- The type parameter @n@ (one of 'N_dnskey', 'N_cdnskey',
-- 'N_key') determines the RR type.  Each has its own type synonym
-- ('T_dnskey', 'T_cdnskey', 'T_key') and matching record pattern
-- synonym ('T_DNSKEY', 'T_CDNSKEY', 'T_KEY') with the
-- corresponding field-name prefix (@dnskey@, @cdnskey@, @key@).
-- The wire format is identical across all three and the type role
-- of @n@ is @phantom@, so the types are mutually coercible; the
-- practical pairing is DNSKEY \<-\> CDNSKEY (mirroring DS \<-\>
-- CDS).
--
-- Note that @T_dnskey@, @T_cdnskey@ and @T_key@ are just type
-- aliases!  The 'T_DNSKEY', 'T_CDNSKEY' and 'T_KEY' record
-- pattern synonyms and their fields are bundled with the
-- underlying 'X_key' data type.  In many cases it is sufficient
-- to import just @X_key(..)@, but if you also need the type
-- aliases, they need to be imported separately:
--
-- > import Net.DNSBase (X_key(..), T_dnskey, T_cdnskey, T_key)
--
-- No embedded domain field, so derived 'Ord' agrees with the
-- canonical wire-form octet ordering
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
--
-- The record pattern synonyms build the corresponding type
-- directly, with their own field-name prefixes:
--
-- > :set -XOverloadedStrings
-- > let dk  = T_DNSKEY  { dnskeyFlags  = 257
-- >                     , dnskeyProto  = 3
-- >                     , dnskeyAlgor  = 13
-- >                     , dnskeyValue  = coerce @Bytes64 "3FOs...Kw==" }
-- >     cdk = T_CDNSKEY { cdnskeyFlags = 257
-- >                     , cdnskeyProto = 3
-- >                     , cdnskeyAlgor = 13
-- >                     , cdnskeyValue = coerce @Bytes64 "3FOs...Kw==" }
-- >  in RData dk : RData cdk : []
--
-- Functions that work on any of the three RR types can use the
-- underscore-prefixed selectors on the shared 'X_key' record:
--
-- > keyAlgVal :: forall n. X_key n -> (DNSKEYAlg, ShortByteString)
-- > keyAlgVal = (,) <$> x_keyAlgor <*> x_keyValue
type role X_key phantom
type X_key :: Nat -> Type
data X_key n = X_KEY
    { x_keyFlags :: Word16          -- ^ Flags
    , x_keyProto :: Word8           -- ^ Protocol
    , x_keyAlgor :: DNSKEYAlg       -- ^ Algorithm
    , x_keyValue :: ShortByteString -- ^ Public Key
    }
deriving instance (KnownSymbol (XkeyConName n)) => Eq (X_key n)
deriving instance (KnownSymbol (XkeyConName n)) => Ord (X_key n)

instance (Nat16 n, KnownSymbol (XkeyConName n)) => Show (X_key n) where
    showsPrec p X_KEY{..} = showsP p $
        showString (symbolVal' (proxy# @(XkeyConName n))) . showChar ' '
        . shows' x_keyFlags    . showChar ' '
        . shows' x_keyProto    . showChar ' '
        . shows' x_keyAlgor    . showChar ' '
        . showKv x_keyValue
      where
        showKv = shows @Bytes64 . coerce

instance (KnownSymbol (XkeyConName n)) => Presentable (X_key n) where
    present X_KEY{..} =
        present     x_keyFlags
        . presentSp x_keyProto
        . presentSp x_keyAlgor
        . presentKv x_keyValue
      where
        presentKv = presentSp @Bytes64 . coerce

instance (Nat16 n, KnownSymbol (XkeyConName n)) => KnownRData (X_key n) where
    rdType _ = RRTYPE $ natToWord16 n
    {-# INLINE rdType #-}
    rdEncode X_KEY{..} = putSizedBuilder $!
        mbWord16   x_keyFlags
        <> mbWord8 x_keyProto
        <> coerce mbWord8 x_keyAlgor
        <> mbShortByteString x_keyValue
    rdDecode _ _ = const do
        x_keyFlags <- get16
        x_keyProto <- get8
        x_keyAlgor <- DNSKEYAlg <$> get8
        x_keyValue <- getShortByteString
        pure $ RData (X_KEY{..} :: X_key n)

-- | Shared wire-format representation for DNSSEC signature
-- records: the @RRSIG@ record
-- ([RFC 4034 section 3](https://datatracker.ietf.org/doc/html/rfc4034#section-3))
-- that signs an RRSet, and the legacy @SIG@ record
-- ([RFC 2535 section 4.1](https://datatracker.ietf.org/doc/html/rfc2535#section-4.1))
-- and its @SIG(0)@ transaction-authentication use
-- ([RFC 2931 section 3](https://datatracker.ietf.org/doc/html/rfc2931#section-3)).
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |        Type Covered           |  Algorithm    |     Labels    |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                         Original TTL                          |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                      Signature Expiration                     |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                      Signature Inception                      |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |            Key Tag            |                               |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         +
-- > |                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-/
-- > /                                                               /
-- > /                            Signature                          /
-- > /                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- The type parameter @n@ (either 'N_rrsig' or 'N_sig') determines
-- the RR type.  Each has its own type synonym ('T_rrsig', 'T_sig')
-- and matching record pattern synonym ('T_RRSIG', 'T_SIG') with
-- the corresponding field-name prefix (@rrsig@, @sig@).  The
-- wire format is shared, but the type role of @n@ is @nominal@:
-- a 'T_sig' value cannot be used where a 'T_rrsig' is expected.
-- This is deliberate — SIG(0) signs a single transaction while
-- RRSIG signs an RRSet, and conflating them at the type level
-- would be unsafe.
--
-- Note that @T_rrsig@ and @T_sig@ are just type aliases!  The 'T_RRSIG' and
-- 'T_SIG' record pattern synonyms and their fields are bundled
-- with the underlying 'X_sig' data type.  In many cases it is
-- sufficient to import just @X_sig(..)@, but if you also need the
-- type aliases, they need to be imported separately:
--
-- > import Net.DNSBase (X_sig(..), T_rrsig, T_sig)
--
-- As noted in
-- [Section 3.1.5 of RFC 4034](https://tools.ietf.org/html/rfc4034#section-3.1.5)
-- the RRsig inception and expiration times use serial number arithmetic.  As a
-- result these timestamps /are not/ pure values, their meaning is
-- time-dependent!  They depend on the present time and are both at most
-- approximately +\/-68 years from the present.  This ambiguity is not a
-- problem because cached RRSIG records should only persist a few days,
-- signature lifetimes should be *much* shorter than 68 years, and key rotation
-- should cause any misconstrued 136-year-old signatures to fail to validate.
-- This also means that the interpretation of a time that is exactly half-way
-- around the clock at @now +\/-0x80000000@ is not important, the signature
-- should never be valid.
--
-- To avoid ambiguity, these *impure* relative values are converted to pure
-- absolute times as they are received from from the network, and converted
-- back to 32-bit values when encoding.  Therefore, the constructor takes
-- absolute 64-bit representations of the inception and expiration times.
--
-- The signer zone name is not subject to wire-form name
-- compression
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- and canonicalises to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2),
-- confirmed by
-- [RFC 6840 section 5.1](https://datatracker.ietf.org/doc/html/rfc6840#section-5.1)).
-- The 'Eq' and 'Ord' instances compare the signer name in
-- canonical wire form (via 'equalWireHost' / 'compareWireHost'),
-- giving stable comparison semantics for general use in ordered
-- collections.  Canonical RR ordering is not a meaningful concept
-- for RRSIG records — they are never themselves signed — so the
-- canonical-ordering machinery from RFC 4034 §6.2 does not apply
-- to them in practice.
--
type role X_sig nominal
type X_sig :: Nat -> Type
data X_sig n = X_SIG
    { x_sigType       :: RRTYPE          -- ^ Type Covered
    , x_sigKeyAlg     :: DNSKEYAlg       -- ^ Algorithm
    , x_sigNumLabels  :: Word8           -- ^ Labels
    , x_sigTTL        :: Word32          -- ^ Original TTL
    , x_sigExpiration :: Int64           -- ^ Signature Expiration
    , x_sigInception  :: Int64           -- ^ Signature Inception
    , x_sigKeyTag     :: Word16          -- ^ Key Tag
    , x_sigZone       :: Domain          -- ^ Signer's Name
    , x_sigValue      :: ShortByteString -- ^ Signature
    }

instance (Nat16 n, KnownSymbol (XsigConName n)) => Show (X_sig n) where
    showsPrec p X_SIG{..} = showsP p $
        showString (symbolVal' (proxy# @(XsigConName n))) . showChar ' '
        . shows' x_sigType       . showChar ' '
        . shows' x_sigKeyAlg     . showChar ' '
        . shows' x_sigNumLabels  . showChar ' '
        . shows' x_sigTTL        . showChar ' '
        . shows' x_sigExpiration . showChar ' '
        . shows' x_sigInception  . showChar ' '
        . shows' x_sigKeyTag     . showChar ' '
        . shows' x_sigZone       . showChar ' '
        . showSv x_sigValue
      where
        showSv = shows @Bytes64 . coerce

-- | Equality of signer names is case-insensitive.
instance (KnownSymbol (XsigConName n)) => Eq  (X_sig n) where
    a == b = (x_sigType       a) == (x_sigType       b)
          && (x_sigKeyAlg     a) == (x_sigKeyAlg     b)
          && (x_sigNumLabels  a) == (x_sigNumLabels  b)
          && (x_sigTTL        a) == (x_sigTTL        b)
          && (x_sigExpiration a) == (x_sigExpiration b)
          && (x_sigInception  a) == (x_sigInception  b)
          && (x_sigKeyTag     a) == (x_sigKeyTag     b)
          && (x_sigZone a) `equalWireHost` (x_sigZone b)
          && (x_sigValue      a) == (x_sigValue      b)

-- | Comparison of signer names is case-insensitive.
instance (KnownSymbol (XsigConName n)) => Ord (X_sig n) where
    a `compare` b = (x_sigType       a) `compare` (x_sigType       b)
                 <> (x_sigKeyAlg     a) `compare` (x_sigKeyAlg     b)
                 <> (x_sigNumLabels  a) `compare` (x_sigNumLabels  b)
                 <> (x_sigTTL        a) `compare` (x_sigTTL        b)
                 <> (x_sigExpiration a) `compare` (x_sigExpiration b)
                 <> (x_sigInception  a) `compare` (x_sigInception  b)
                 <> (x_sigKeyTag     a) `compare` (x_sigKeyTag     b)
                 <> (x_sigZone a) `compareWireHost` (x_sigZone     b)
                 <> (x_sigValue      a) `compare` (x_sigValue      b)

instance (KnownSymbol (XsigConName n)) => Presentable (X_sig n) where
    present X_SIG{..} =
        present     x_sigType
        . presentSp x_sigKeyAlg
        . presentSp x_sigNumLabels
        . presentSp x_sigTTL
        . presentEp x_sigExpiration
        . presentEp x_sigInception
        . presentSp x_sigKeyTag
        . presentSp x_sigZone
        . presentSv x_sigValue
      where
        presentEp = presentSp @Epoch64 . coerce
        presentSv = presentSp @Bytes64 . coerce

instance (Nat16 n, KnownSymbol (XsigConName n)) => KnownRData (X_sig n) where
    rdType _ = RRTYPE $ natToWord16 n
    {-# INLINE rdType #-}
    rdEncode X_SIG{..} = putSizedBuilder $
        coerce mbWord16     x_sigType
        <> coerce mbWord8   x_sigKeyAlg
        <> mbWord8          x_sigNumLabels
        <> mbWord32         x_sigTTL
        <> coerce clock     x_sigExpiration
        <> coerce clock     x_sigInception
        <> mbWord16         x_sigKeyTag
        <> mbWireForm       x_sigZone
        <> mbShortByteString x_sigValue
      where
        clock :: Int64 -> SizedBuilder
        clock = mbWord32 . fromIntegral
    cnEncode X_SIG{..} = putSizedBuilder $
        coerce mbWord16     x_sigType
        <> coerce mbWord8   x_sigKeyAlg
        <> mbWord8          x_sigNumLabels
        <> mbWord32         x_sigTTL
        <> coerce clock     x_sigExpiration
        <> coerce clock     x_sigInception
        <> mbWord16         x_sigKeyTag
        <> mbWireForm (canonicalise x_sigZone)
        -- | Canonical encoding of the RRSIG omits the signature value.
      where
        clock :: Int64 -> SizedBuilder
        clock = mbWord32 . fromIntegral
    rdDecode _ _ = const do
        x_sigType       <- RRTYPE <$> get16
        x_sigKeyAlg     <- DNSKEYAlg <$> get8
        x_sigNumLabels  <- get8
        x_sigTTL        <- get32
        x_sigExpiration <- getDnsTime
        x_sigInception  <- getDnsTime
        x_sigKeyTag     <- get16
        x_sigZone       <- getDomainNC
        x_sigValue      <- getShortByteString
        pure $ RData (X_SIG{..} :: X_sig n)

-- | The @ZONEMD@ resource record
-- ([RFC 8976 section 2.2](https://www.rfc-editor.org/rfc/rfc8976#section-2.2))
-- — a digest of the zone contents, used by recipients of zone
-- transfers to verify zone integrity end-to-end.  Four fields:
-- a 32-bit serial number matching the SOA, an 8-bit scheme
-- selector, an 8-bit hash-algorithm selector, and the digest
-- bytes.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                             Serial                            |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |    Scheme     |Hash Algorithm |                               |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
-- > |                             Digest                            |
-- > /                                                               /
-- > /                                                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- No embedded domain field, so derived 'Ord' agrees with the
-- canonical wire-form octet ordering.
data T_zonemd = T_ZONEMD
    { zonemdSerial  :: Word32 -- ^ Serial
    , zonemdScheme  :: Word8  -- ^ Scheme
    , zonemdHashAlg :: Word8  -- ^ Hash Algorithm
    , zonemdDigest  :: ShortByteString -- ^ Digest
    } deriving (Eq, Ord)

instance Show T_zonemd where
    showsPrec p T_ZONEMD{..} = showsP p $
        showString "X_SIG"     . showChar ' '
        . shows' zonemdSerial  . showChar ' '
        . shows' zonemdScheme  . showChar ' '
        . shows' zonemdHashAlg . showChar ' '
        . showMd zonemdDigest
      where
        showMd = shows @Bytes16 . coerce

instance Presentable T_zonemd where
    present T_ZONEMD{..} =
        present   zonemdSerial
        . presentSp zonemdScheme
        . presentSp zonemdHashAlg
        . presentMd zonemdDigest
      where
        presentMd d | SB.null d = present @String " ( )"
                    | otherwise = presentSp @Bytes16 (coerce d)

instance KnownRData T_zonemd where
    rdType _ = ZONEMD
    {-# INLINE rdType #-}
    rdEncode T_ZONEMD{..}
        | SB.length (coerce zonemdDigest) < 12
        = failWith CantEncode
        | otherwise
        = putSizedBuilder $
            mbWord32 zonemdSerial
            <> mbWord8 zonemdScheme
            <> mbWord8 zonemdHashAlg
            <> mbShortByteString zonemdDigest
    rdDecode _ _ len
        | len < 18 = failSGet "ZONEMD digest too short"
        | otherwise = do
            zonemdSerial    <- get32
            zonemdScheme    <- get8
            zonemdHashAlg   <- get8
            zonemdDigest    <- getShortByteString
            pure $ RData T_ZONEMD{..}

-- | The @IPSECKEY@ resource record
-- ([RFC 4025 section 2.1](https://datatracker.ietf.org/doc/html/rfc4025#section-2.1))
-- — IPsec keying material for a host or subnet.
--
-- >   0                   1                   2                   3
-- >   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >  |  precedence   | gateway type  |  algorithm    |   gateway     |
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+---------------+               +
-- >  ~                            gateway                            ~
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- >  |                                                               /
-- >  /                          public key                           /
-- >  /                                                               /
-- >  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|
--
-- The /gateway type/ byte selects one of four defined gateway shapes
-- (none, IPv4, IPv6, or FQDN); the /gateway/ field carries the
-- corresponding value, and the trailing /public key/ holds the key
-- bytes.
--
-- For future or otherwise unrecognised gateway types (any value
-- outside 0..3) the wire-form boundary between the gateway and the
-- public key is unknown to the parser, so both are kept together as
-- a single opaque blob inside 'IPSecKeyGWG', and the @key@ component
-- below is then empty.
--
-- The constructors are not exported; the only public view is the
-- 'IPSecKey' bidirectional pattern synonym, which exposes a uniform
-- five-argument tuple @(precedence, gateway type, algorithm,
-- gateway, public key)@ regardless of the gateway shape.
--
type T_ipseckey :: Type
data T_ipseckey
    = IPSecX_ Word8 Word8 ShortByteString        -- ^ No gateway (type 0); fields: precedence, algorithm, public key.
    | IPSec4_ Word8 Word8 IPv4 ShortByteString   -- ^ IPv4 gateway (type 1); fields: precedence, algorithm, gateway, public key.
    | IPSec6_ Word8 Word8 IPv6 ShortByteString   -- ^ IPv6 gateway (type 2); fields: precedence, algorithm, gateway, public key.
    | IPSecD_ Word8 Word8 Domain ShortByteString -- ^ FQDN gateway (type 3); fields: precedence, algorithm, gateway, public key.
    | IPSecG_ Word8 Word8 Word8 ShortByteString  -- ^ Future or unrecognised gateway type (\>3); fields: precedence, gateway type, algorithm, opaque (gateway+key) blob.
   deriving (Eq, Show)

instance Ord T_ipseckey where
    (IPSecKey pa ta aa ga ka) `compare` (IPSecKey pb tb ab gb kb) =
        pa `compare` pb
        <> ta `compare` tb
        <> aa `compare` ab
        <> ga `compare` gb
        <> ka `compare` kb

instance Presentable T_ipseckey where
    present (IPSecKey p t a g k)
        | IPSecKeyGWG bytes <- g = \kont -> present "\\#"
            $ presentSp (3 + SB.length bytes)
            $ B.char8 ' ' <> B.word8HexFixed p <> B.word8HexFixed t <> B.word8HexFixed a
              <> present @Bytes16 (coerce bytes) kont
        | otherwise = present p
                    . presentSp t
                    . presentSp a
                    . presentSp g
                    . presentSp @Bytes64 (coerce k)

instance KnownRData T_ipseckey where
    rdType _ = IPSECKEY
    {-# INLINE rdType #-}
    rdEncode (IPSecKey p t a g k) = putSizedBuilder $
        mbWord8 p <> mbWord8 t <> mbWord8 a <> mbgk g
      where
        mbgk IPSecKeyGWX      = mbShortByteString k
        mbgk (IPSecKeyGW4 ip) = mbIPv4 ip <> mbShortByteString k
        mbgk (IPSecKeyGW6 ip) = mbIPv6 ip <> mbShortByteString k
        mbgk (IPSecKeyGWD dn) = mbWireForm dn <> mbShortByteString k
        mbgk (IPSecKeyGWG gk)  = mbShortByteString gk
    rdDecode _ _ = const do
        p <- get8
        t <- get8
        a <- get8
        case t of
            0 -> RData . IPSecX_ p a <$> getShortByteString
            1 -> RData <$.> IPSec4_ p a <$> getIPv4 <*> getShortByteString
            2 -> RData <$.> IPSec6_ p a <$> getIPv6 <*> getShortByteString
            3 -> RData <$.> IPSecD_ p a <$> getDomain <*> getShortByteString
            _ -> RData . IPSecG_ p t a <$> getShortByteString

-- | Uniform five-argument view of an 'T_ipseckey' record.
--
-- When matching against an existing record, /gateway type/ and
-- /gateway/ are always consistent (an 'IPSecKeyGW4' value implies
-- @gateway type == 1@, and so on).
--
-- When /constructing/ a record, the /gateway type/ and /gateway/
-- arguments must agree, and for unrecognised gateway types
-- (anything outside 0..3) the /public key/ argument must be empty
-- (the parser cannot find the boundary, so the gateway-and-key
-- bytes live together inside the 'IPSecKeyGWG' payload).  Valid
-- combinations are:
--
-- * @0@ with 'IPSecKeyGWX' — no gateway
-- * @1@ with 'IPSecKeyGW4' — IPv4 gateway
-- * @2@ with 'IPSecKeyGW6' — IPv6 gateway
-- * @3@ with 'IPSecKeyGWD' — FQDN gateway
-- * any other type byte with 'IPSecKeyGWG' and empty key
--
-- Any other combination raises a runtime error.
pattern IPSecKey :: Word8 -- ^ precedence
                 -> Word8 -- ^ gateway type
                 -> Word8 -- ^ algorithm
                 -> IPSecKeyGateway -- ^ gateway
                 -> ShortByteString -- ^ public key
                 -> T_ipseckey
pattern IPSecKey p t a g k <- (ipSecDecon -> (p, t, a, g, k)) where
    IPSecKey p 0 a IPSecKeyGWX k      = IPSecX_ p a k
    IPSecKey p 1 a (IPSecKeyGW4 ip) k = IPSec4_ p a ip k
    IPSecKey p 2 a (IPSecKeyGW6 ip) k = IPSec6_ p a ip k
    IPSecKey p 3 a (IPSecKeyGWD dn) k = IPSecD_ p a dn k
    IPSecKey p t a (IPSecKeyGWG gk) (SB.null -> True) = IPSecG_ p t a gk
    IPSecKey _ _ _ _ _ = error "Invalid IPSECKEY parameters"
{-# COMPLETE IPSecKey #-}

ipSecDecon :: T_ipseckey
           -> (Word8, Word8, Word8, IPSecKeyGateway, ShortByteString)
ipSecDecon (IPSecX_ p a k)    = (p, 0, a, IPSecKeyGWX,    k)
ipSecDecon (IPSec4_ p a ip k) = (p, 1, a, IPSecKeyGW4 ip, k)
ipSecDecon (IPSec6_ p a ip k) = (p, 2, a, IPSecKeyGW6 ip, k)
ipSecDecon (IPSecD_ p a dn k) = (p, 3, a, IPSecKeyGWD dn, k)
ipSecDecon (IPSecG_ p t a gk) = (p, t, a, IPSecKeyGWG gk, mempty)
{-# INLINE ipSecDecon #-}

-- | Shape of an 'IPSECKEY' record's /gateway/ field.  Four cases
-- match the four gateway types defined by RFC 4025; the catchall
-- 'IPSecKeyGWG' covers any future or otherwise unrecognised gateway
-- type byte and holds the gateway and public-key bytes together as
-- a single opaque blob (the parser has no way to find the boundary
-- between them when the shape is unknown).
data IPSecKeyGateway
    = IPSecKeyGWX                 -- ^ No gateway (gateway type 0).
    | IPSecKeyGW4 IPv4            -- ^ IPv4 gateway address (gateway type 1).
    | IPSecKeyGW6 IPv6            -- ^ IPv6 gateway address (gateway type 2).
    | IPSecKeyGWD Domain          -- ^ FQDN gateway (gateway type 3); not subject to name compression.
    | IPSecKeyGWG ShortByteString -- ^ Future or unrecognised gateway type (\>3); opaque gateway-and-key blob.
  deriving (Eq, Ord, Show)

instance Presentable IPSecKeyGateway where
    present IPSecKeyGWX      = present '.'
    present (IPSecKeyGW4 ip) = present ip
    present (IPSecKeyGW6 ip) = present ip
    present (IPSecKeyGWD dn) = present dn
    present _                = id

-- | Compute RFC 4034, Appendix B key tag over the DNSKEY RData: 16 bit flags,
-- 8 bit proto, 8 bit alg and key octets.
--
-- With the obsolete algorithm 1 we assign key tag 0 to truncated keys, but
-- RSAMD5 keys are no longer seen in the wild.  We check that the modulus
-- actually has at least 3 octets.
--
keytag :: X_key n -> Word16
keytag = fromIntegral . go
  where
    go :: X_key n -> Word32
    go X_KEY{..} | alg /= 1 = tag
      where
        (DNSKEYAlg alg) = x_keyAlgor
        !z   = lo x_keyFlags + hi x_keyProto + lo alg
        ws32 = zipWith ($) (cycle [hi, lo]) $ SB.unpack x_keyValue
        !raw = foldl' (+) z ws32
        !tag = (raw + (raw `shiftR` 16)) .&. 0xffff
    go X_KEY{..} | Just !tag <- c32 = tag
                    | otherwise = 0
      where
        len = SB.length x_keyValue
        c32 = (+) <$> (hi <$.> SB.indexMaybe x_keyValue (len - 3))
                  <*> (lo <$.> SB.indexMaybe x_keyValue (len - 2))

    hi, lo :: Integral a => a -> Word32
    lo = fromIntegral
    hi = flip shiftL 8 . lo
