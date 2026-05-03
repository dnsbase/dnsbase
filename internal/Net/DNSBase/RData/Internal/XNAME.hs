-- |
-- Module      : Net.DNSBase.RData.Internal.XNAME
-- Description : Internal: shared codec for domain-valued RR types
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
--
-- The 'X_domain' newtype represents the RFC 1035 RR types whose
-- RDATA is a single domain name: 'T_ns', 'T_cname', 'T_ptr' and
-- the obsolete mailbox-pointer types 'T_md', 'T_mf', 'T_mb',
-- 'T_mg', 'T_mr'.  'T_dname' (RFC 6672) lives here too because it
-- has the same shape — a single 'Domain' — but it gets its own
-- newtype because its wire-form codec differs (no name
-- compression on encode).
--
-- The public API is in "Net.DNSBase.RData.XNAME" for the
-- non-obsolete subset and in "Net.DNSBase.RData.Obsolete" for the
-- old mailbox-pointer types.
{-# LANGUAGE
    MagicHash
  , UndecidableInstances
  #-}

module Net.DNSBase.RData.Internal.XNAME
    ( -- * Domain-name-valued RR types.
      -- ** Well-known (from RFC1035)
      X_domain(T_NS, T_CNAME, T_PTR, T_MB, T_MD, T_MF, T_MG, T_MR)
    , type XdomainConName, T_ns, T_cname, T_ptr, T_mb, T_md, T_mf, T_mg, T_mr
      -- ** @DNAME@
    , T_dname(..)
    ) where

import GHC.Exts (proxy#)
import GHC.TypeLits as TL (TypeError, ErrorMessage(..))
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal')

import Net.DNSBase.Decode.Internal.Domain
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.Nat16
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.Util

type XdomainConName :: Nat -> Symbol
type family XdomainConName n where
    XdomainConName N_ns      = "T_NS"
    XdomainConName N_cname   = "T_CNAME"
    XdomainConName N_ptr     = "T_PTR"
    XdomainConName N_md      = "T_MD"
    XdomainConName N_mf      = "T_MF"
    XdomainConName N_mb      = "T_MB"
    XdomainConName N_mg      = "T_MG"
    XdomainConName N_mr      = "T_MR"
    XdomainConName n         = TypeError
                             ( ShowType n
                               :<>: TL.Text " is not an RFC1035 domain-valued RRTYPE" )

-- | X_domain specialised to @NS@ records.
type T_ns      = X_domain N_ns
-- | X_domain specialised to @CNAME@ records.
type T_cname   = X_domain N_cname
-- | X_domain specialised to @PTR@ records.
type T_ptr     = X_domain N_ptr
-- | X_domain specialised to @MD@ records.
type T_md      = X_domain N_md
-- | X_domain specialised to @MF@ records.
type T_mf      = X_domain N_mf
-- | X_domain specialised to @MB@ records.
type T_mb      = X_domain N_mb
-- | X_domain specialised to @MG@ records.
type T_mg      = X_domain N_mg
-- | X_domain specialised to @MR@ records.
type T_mr      = X_domain N_mr

-- | Authoritative name server for a delegated zone
-- ([RFC 1035 section 3.3.11](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.11)).
pattern  T_NS :: Domain -> T_ns
pattern  T_NS d = (X_DOMAIN d :: T_ns)
{-# COMPLETE T_NS #-}
-- | Canonical-name alias for the owner name
-- ([RFC 1035 section 3.3.1](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.1)).
pattern  T_CNAME :: Domain -> T_cname
pattern  T_CNAME d = (X_DOMAIN d :: T_cname)
{-# COMPLETE T_CNAME #-}
-- | Domain-name pointer, typically used for reverse mapping
-- ([RFC 1035 section 3.3.12](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.12)).
pattern  T_PTR :: Domain -> T_ptr
pattern  T_PTR d = (X_DOMAIN d :: T_ptr)
{-# COMPLETE T_PTR #-}
-- | Mail destination
-- ([RFC 1035 section 3.3.4](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.4);
-- obsolete — use 'Net.DNSBase.RData.SRV.T_mx').
pattern  T_MD :: Domain -> T_md
pattern  T_MD d = (X_DOMAIN d :: T_md)
{-# COMPLETE T_MD #-}
-- | Mail forwarder
-- ([RFC 1035 section 3.3.5](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.5);
-- obsolete — use 'Net.DNSBase.RData.SRV.T_mx').
pattern  T_MF :: Domain -> T_mf
pattern  T_MF d = (X_DOMAIN d :: T_mf)
{-# COMPLETE T_MF #-}
-- | Mailbox domain
-- ([RFC 1035 section 3.3.3](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.3);
-- obsolete).
pattern  T_MB :: Domain -> T_mb
pattern  T_MB d = (X_DOMAIN d :: T_mb)
{-# COMPLETE T_MB #-}
-- | Mail group member
-- ([RFC 1035 section 3.3.6](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.6);
-- obsolete).
pattern  T_MG :: Domain -> T_mg
pattern  T_MG d = (X_DOMAIN d :: T_mg)
{-# COMPLETE T_MG #-}
-- | Mail rename
-- ([RFC 1035 section 3.3.8](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.8);
-- obsolete).
pattern  T_MR :: Domain -> T_mr
pattern  T_MR d = (X_DOMAIN d :: T_mr)
{-# COMPLETE T_MR #-}

-- | Shared wire-format representation for the RFC 1035 RR types
-- whose RDATA is a single domain name: @NS@
-- ([section 3.3.11](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.11)),
-- @CNAME@
-- ([section 3.3.1](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.1)),
-- @PTR@
-- ([section 3.3.12](https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.12)),
-- and the obsolete mailbox-pointer types @MB@, @MD@, @MF@, @MG@,
-- @MR@ (RFC 1035 sections 3.3.3-3.3.8).  The type parameter @n@
-- (one of 'N_ns', 'N_cname', 'N_ptr', 'N_mb', 'N_md', 'N_mf',
-- 'N_mg', 'N_mr') determines the RR type.  Each has its own type
-- synonym ('T_ns', 'T_cname', ...) and matching pattern synonym
-- ('T_NS', 'T_CNAME', ...).
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                 DOMAINNAME                    /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- Although all these RR types share a common underlying
-- representation, the constructors are not shared and the types
-- are not mutually coercible — this is deliberate, to catch
-- RR-type confusion at compile time.
--
-- The target domain is subject to wire-form name compression on
-- encode
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- and canonicalises to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare in canonical wire form
-- (via 'equalWireHost' / 'compareWireHost'), so 'Ord' is
-- canonical.  Presentation preserves the original case.
type X_domain :: Nat -> Type
type role X_domain nominal
newtype X_domain n = X_DOMAIN Domain

instance (Nat16 n, KnownSymbol (XdomainConName n)) => Show (X_domain n) where
    showsPrec p (X_DOMAIN d) = showsP p $
        showString (symbolVal' (proxy# @(XdomainConName n))) . showChar ' '
        . shows' d

-- | Case-insensitive wire-form equality.
instance Eq (X_domain f) where
    a == b = coerce a `equalWireHost` coerce b

-- | Case-insensitive wire-form order.
instance Ord (X_domain f) where
    a `compare` b = coerce a `compareWireHost` coerce b

-- | Presentation form preserves case.
instance Presentable (X_domain f) where
    present = present @Domain . coerce

-- | Name compression used on input and output.
instance (Typeable n, Nat16 n, KnownSymbol (XdomainConName n))
    => KnownRData (X_domain n) where
    rdType _ = RRTYPE $ natToWord16 n
    {-# INLINE rdType #-}
    rdEncode = putDomain . coerce
    cnEncode = putSizedBuilder . mbWireForm . canonicalise . coerce
    rdDecode _ _ = const do
        RData . X_DOMAIN @n <$> getDomain

-- | The @DNAME@ resource record
-- ([RFC 6672 section 2.1](https://tools.ietf.org/html/rfc6672#section-2.1))
-- — redirection for a subtree of the domain-name space: a 'Domain'
-- naming the target subtree under which queries are rewritten.
--
-- The target field is not subject to wire-form name compression
-- on encode
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- but canonicalises to lower case
-- ([RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)).
-- The 'Eq' and 'Ord' instances compare in canonical wire form
-- (via 'equalWireHost' / 'compareWireHost'), so 'Ord' is
-- canonical.  Presentation preserves the original case.
--
-- See 'X_domain' for the sibling family of RFC 1035 single-domain
-- RR types, which differ from @DNAME@ in that they do use name
-- compression on encode.
newtype T_dname = T_DNAME Domain -- ^ Target 'Domain'
    deriving (Show)

-- | Case-insensitive wire-form equality.
instance Eq T_dname where
    a == b = coerce a `equalWireHost` coerce b

-- | Case-insensitive wire-form order.
instance Ord T_dname where
    a `compare` b = coerce a `compareWireHost` coerce b

-- | Presentation form preserves case.
instance Presentable T_dname where
    present = present @Domain . coerce

-- | Name compression used on input only.
instance KnownRData T_dname where
    rdType _ = DNAME
    {-# INLINE rdType #-}
    rdEncode = putSizedBuilder . mbWireForm . coerce
    cnEncode = putSizedBuilder . mbWireForm . canonicalise . coerce
    rdDecode _ _ = const do
        RData . T_DNAME <$> getDomainNC
