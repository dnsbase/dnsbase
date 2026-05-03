{-|
Module      : Net.DNSBase.Text
Description : Text wrappers and zone-file string-presentation helpers
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

Newtype wrappers that tag a byte string with a particular
text-shaped presentation form: 'DnsText' renders an opaque
byte sequence as a DNS character-string with the standard
@\\DDD@ escaping for non-printable bytes, and 'DnsUtf8Text'
renders a UTF-8 'Data.Text.Text' value with the same escape rules.  The
'presentCharString', 'presentDomainLabel', and
'presentHostLabel' helpers handle the per-context escape sets
(character-strings, domain labels, and the stricter hostname
form respectively).  'presentCSVList' formats a comma-separated
list value as used by multi-valued SVCB parameters.
-}

module Net.DNSBase.Text
    ( DnsText(..)
    , DnsUtf8Text(..)
    , dnsTextCmp
    , presentCharString
    , presentDomainLabel
    , presentHostLabel
    , presentCSVList
    ) where

import Net.DNSBase.Internal.Text
