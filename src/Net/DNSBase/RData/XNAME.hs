{-|
Module      : Net.DNSBase.RData.XNAME
Description : Domain-name-valued RR types (NS, CNAME, PTR, DNAME)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The classical RR types from RFC 1035 whose RDATA is a single
domain name: 'T_ns' (delegation), 'T_cname' (canonical-name
alias), and 'T_ptr' (reverse-mapping pointer).  All three share
the 'X_domain' newtype underneath, but the types are nominally
distinct so a CNAME value can't be used where a PTR is expected
(and vice versa).

'T_dname' (RFC 6672) is exported alongside because it has the
same shape — a single 'Net.DNSBase.Domain.Domain' — though it does not share the
codec: @DNAME@'s target is not subject to wire-form name
compression on encode.

The obsolete mailbox-pointer types @MB@, @MD@, @MF@, @MG@,
@MR@ are also 'X_domain' instances but live in
"Net.DNSBase.RData.Obsolete".
-}

module Net.DNSBase.RData.XNAME
    ( -- * RR types representing a single domain name
      X_domain(T_NS, T_PTR, T_CNAME)
    , type XdomainConName, T_ns, T_ptr, T_cname, T_dname(..)
    ) where

import Net.DNSBase.RData.Internal.XNAME
