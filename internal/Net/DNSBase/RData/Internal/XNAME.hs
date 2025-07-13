{-# LANGUAGE UndecidableInstances #-}

module Net.DNSBase.RData.Internal.XNAME
    ( -- * Domain-name-valued RR types.
      -- ** Well-known (from RFC1035)
      X_domain(T_NS, T_CNAME, T_PTR, T_MB, T_MD, T_MF, T_MG, T_MR)
    , T_ns, T_cname, T_ptr, T_mb, T_md, T_mf, T_mg, T_mr
      -- ** @DNAME@
    , T_dname(..)
    ) where

import GHC.TypeLits (TypeError, ErrorMessage(..))
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal)

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
                               :<>: Text " is not an RFC1035 domain-valued RRTYPE" )

-- | All these are structurally identical.
type T_ns      = X_domain N_ns
type T_cname   = X_domain N_cname
type T_ptr     = X_domain N_ptr
type T_md      = X_domain N_md
type T_mf      = X_domain N_mf
type T_mb      = X_domain N_mb
type T_mg      = X_domain N_mg
type T_mr      = X_domain N_mr

-- | Interpret an 'X_domain' structure of subtype 'N_ns' as a 'T_ns'.
{-# COMPLETE T_NS #-}
pattern  T_NS :: Domain -> T_ns
pattern  T_NS d = (X_DOMAIN d :: T_ns)
-- | Interpret an 'X_domain' structure of subtype 'N_cname' as a 'T_cname'.
{-# COMPLETE T_CNAME #-}
pattern  T_CNAME :: Domain -> T_cname
-- | Interpret an 'X_domain' structure of subtype 'N_ptr' as a 'T_ptr'.
{-# COMPLETE T_PTR #-}
pattern  T_PTR :: Domain -> T_ptr
pattern  T_PTR d = (X_DOMAIN d :: T_ptr)
-- | Interpret an 'X_domain' structure of subtype 'N_md' as a 'T_md'.
{-# COMPLETE T_MD #-}
pattern  T_MD :: Domain -> T_md
pattern  T_MD d = (X_DOMAIN d :: T_md)
-- | Interpret an 'X_domain' structure of subtype 'N_mf' as a 'T_mf'.
{-# COMPLETE T_MF #-}
pattern  T_MF :: Domain -> T_mf
pattern  T_MF d = (X_DOMAIN d :: T_mf)
pattern  T_CNAME d = (X_DOMAIN d :: T_cname)
-- | Interpret an 'X_domain' structure of subtype 'N_mb' as a 'T_mb'.
{-# COMPLETE T_MB #-}
pattern  T_MB :: Domain -> T_mb
pattern  T_MB d = (X_DOMAIN d :: T_mb)
-- | Interpret an 'X_domain' structure of subtype 'N_mg' as a 'T_mg'.
{-# COMPLETE T_MG #-}
pattern  T_MG :: Domain -> T_mg
pattern  T_MG d = (X_DOMAIN d :: T_mg)
-- | Interpret an 'X_domain' structure of subtype 'N_mr' as a 'T_mr'.
{-# COMPLETE T_MR #-}
pattern  T_MR :: Domain -> T_mr
pattern  T_MR d = (X_DOMAIN d :: T_mr)

-- | [CNAME RDATA](http://datatracker.ietf.org/doc/html/rfc1035#section-3.3.1),
--   [NS RDATA](http://datatracker.ietf.org/doc/html/rfc1035#section-3.3.11),
--   [PTR RDATA](http://datatracker.ietf.org/doc/html/rfc1035#section-3.3.12),
--   [MB RDATA](http://datatracker.ietf.org/doc/html/rfc1035#section-3.3.3),
--   [MD RDATA](http://datatracker.ietf.org/doc/html/rfc1035#section-3.3.4),
--   [MF RDATA](http://datatracker.ietf.org/doc/html/rfc1035#section-3.3.5),
--   [MG RDATA](http://datatracker.ietf.org/doc/html/rfc1035#section-3.3.6),
--   [MR RDATA](http://datatracker.ietf.org/doc/html/rfc1035#section-3.3.8).
--
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                 DOMAINNAME                    /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- Though all the RR types share a common underlying representation, to help
-- avoid inadvertent mistakes, the common constructor is not shared and the
-- types are not mutually coercible.
--
-- The target domain name is subject to
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4),
-- and canonicalises to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- - Equality and comparison are case-insensitive.
-- - Order is wire-form
--   [canonical](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
type X_domain :: Nat -> Type
type role X_domain nominal
newtype X_domain n = X_DOMAIN Domain
    deriving (Typeable)

instance (Nat16 n, KnownSymbol (XdomainConName n)) => Show (X_domain n) where
    showsPrec p (X_DOMAIN d) = showsP p $
        showString (symbolVal (Proxy @(XdomainConName n))) . showChar ' '
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
    rdType _ = RRTYPE $ natToWord16 @n
    {-# INLINE rdType #-}
    rdEncode = putDomain . coerce
    cnEncode = putSizedBuilder . mbWireForm . canonicalise . coerce
    rdDecode _ _ = const do
        RData . X_DOMAIN @n <$> getDomain

-- | [DNAME RDATA](https://tools.ietf.org/html/rfc6672#section-2.1).
-- Redirection for a subtree of the domain name tree.
--
-- [Name compression](<https://datatracker.ietf.org/doc/html/rfc3597#section-4)
-- on input, but not on output.
-- DNAMEs canonicalise to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- - Equality and order are case-insensitive.
-- - Order is wire-form
--   [canonical](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
newtype T_dname = T_DNAME Domain -- ^ Target 'Domain'
    deriving (Typeable, Show)

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
