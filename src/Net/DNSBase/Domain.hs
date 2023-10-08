-- |
-- Module      : Network.StubDNS.Domain
-- Description : Domain/mailbox name data-type
-- Copyright   : (c) Viktor Dukhovni, 2020
--               (c) Peter Duchovni, 2020
-- License     : BSD-style
--
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
-- Portability : non-portable (GHC-8.8 and later only)
--
-- The 'Domain' data type represents the /wire form/ of DNS domain names or
-- mailbox names.  The internal representation is not exposed, but is basically
-- a 'ShortByteString' containing a sequence of length-prefixed A-labels,
-- without a terminal empty label.  The labels must not be longer than 63
-- octets, and the total length of the /wire form/ must not exceed 254 bytes
-- (255 when serialized into DNS messages with a terminal empty label).
--
-- The distinction between domain names and mailbox names exists only at the
-- level of /presentation form/, and they are otherwise the same.  The standard
-- /presentation form/ of a 'Domain' uses @\'.\'@ as a label separator,
-- escaping any (rare) literal @\'.\'@ characters that happen to be part of the
-- label content, and a terminal dot is appended to the last label.  As a matter
-- of convenience, this module introduces an ad hoc /mailbox presentation form/
-- of a multi-label 'Domain', which uses @\'\@\'@ as the separator between
-- the first and second labels, and any literal @\'.\'@ characters in the first
-- label are not escaped.  In the mailbox presentation form, no terminal @\'.\'@
-- is appended to the address.
--
-- As "ShortByteString" values, labels are composed of arbitrary 'Word8'
-- elements.  The only constraint is that each label is at most 63 bytes.
--
-- This module implements Template Haskell /splices/ for literal domain names
-- in application source files.  Literal strings are validated and converted to
-- /wire form/ at compile-time.  The syntax is:
--
-- > let d = $$(dnLit "haskell.example.com") :: Domain
-- > let m = $$(mbLit "some.user@example.com") :: Domain
--
-- This module also provides an 'IsString' instance, which performs domainname
-- conversion from string literals at run-time, raising a run-time error if the
-- input is invalid.  Though this is more concise, it is less safe and less
-- efficient, choose wisely.

module Net.DNSBase.Domain
    ( -- ** Domain data type
      Domain(RootDomain)
    , DnsTriple(..)
    , Host
    , fromHost
    , toHost
    , Mbox
    , fromMbox
    , toMbox
    -- ** Domain name literals
    , dnLit
    , mbLit
    -- ** Conversions
    -- *** From/to presentation form
    , parseDomain
    , parseMbox
    , strToDomain
    , strToMbox
    -- *** Canonicalisation to lower case
    , canonicalise
    -- *** Working with labels
    , appendDomain
    , consDomain
    , unconsDomain
    , labelCount
    , fromLabels
    , toLabels
    , revLabels
    , commonSuffix
    -- ** Binary serialization functions
    , shortBytes
    , wireBytes
    , mbWireForm
    -- ** Predicates
    , isLDHName
    , isLDHLabel
    -- ** Sorting and comparison
    , compareWireHost
    , equalWireHost
    , canonicalNameOrder
    , sortDomains
    ) where

import Net.DNSBase.Internal.Domain
