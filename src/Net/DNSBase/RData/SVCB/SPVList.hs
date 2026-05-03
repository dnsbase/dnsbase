{-|
Module      : Net.DNSBase.RData.SVCB.SPVList
Description : Internal helper for presenting comma-separated SVCB value lists
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

A small helper used by the multi-valued SVCB service-parameter
types ('Net.DNSBase.RData.SVCB.SPV_alpn' and friends) to emit their values in the
RFC 9460 comma-separated zone-file form.
-}

module Net.DNSBase.RData.SVCB.SPVList
    ( presentSPVList
    ) where

import Net.DNSBase.Internal.Util

import Net.DNSBase.Text

-- | Render a non-empty list of byte-string values as a single
-- comma-separated DNS character-string, in the form expected for
-- multi-valued service parameters such as @alpn@.
presentSPVList :: (NonEmpty ShortByteString) -> Builder -> Builder
presentSPVList (v :| vs) = presentCSVList (v : vs)
