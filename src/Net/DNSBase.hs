{-# OPTIONS_GHC -Wno-duplicate-exports #-}
{-|
Module      : Net.DNSBase
Description : DNS Stub resolver
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

A DNS stub-resolver library with a typed 'RData' model and a
runtime extension API.  The IO layer is derived from Kazu
Yamamoto's [@dns@](https://hackage.haskell.org/package/dns)
package; what @dnsbase@ layers on top sits in the RR-data model
and the configuration story.

Every RR type's payload is modeled via a dedicated Haskell type
— these include, for example, the recent SVCB \/ HTTPS
service-binding records, with up-to-date extensible SvcParam
coverage.  EDNS option support includes Extended DNS Errors
(EDE) with a user-extensible info-code name table.  Coverage of
both widely used and historical DNS RR types is comprehensive —
only the most marginal obsolete or experimental types remain
unimplemented.  Individual payloads are held uniformly inside
the existential 'RData' wrapper, so an 'RR' value can carry any
type's data.

The basic lookup interface ('lookupA', 'lookupMX', 'lookupTXT',
…) is deliberately similar to @dns@; the differences are
concentrated in the typed-data layer and the configuration
surface.

== Extending the library

Applications can extend the library with any /missing/ RRTYPEs,
EDNS(0) options, or SVCB and HTTPS service parameter values.
Application-specified data types take precedence over any existing
or later added built-in implementations.

Extensions are registered by constructing a pure resolver
configuration value, rather than via IO actions on mutable
global state.  Adding custom data types to the library does not
require a source-code fork.  See
[Adding a custom RR type]("Net.DNSBase.Extensible#customRRtype")
and
[Adding a custom EDNS option]("Net.DNSBase.Extensible#customEDNS")
for detailed examples.

== Concurrency

Like its @dns@ ancestor, @dnsbase@ scales well to thousands of
@forkIO@ threads, with throughput of around ten thousand
distinct queries (not even cache hits) per second observed when
given sufficient concurrency, a high file descriptor limit and
a cooperative upstream iterative resolver.

A single 'ResolvSeed' configuration can be used to derive
per-thread 'Resolver' instances via 'withResolver'.  As in
@dns@, concurrent use of the same 'Resolver' in multiple
threads is not supported.

== A minimal example

> import Net.DNSBase
> import Control.Exception (throwIO)
> import System.IO (stdout)
>
> main :: IO ()
> main = makeResolvSeed defaultResolvConf >>= \ case
>   Left  e    -> throwIO e
>   Right seed -> withResolver seed \ r ->
>     lookupMX r $$(dnLit8 "ietf.org") >>= \ case
>       Left  e   -> throwIO e
>       Right mxs -> hPutBuilder stdout $ foldr presentLn mempty mxs

'makeResolvSeed' builds a 'ResolvSeed' from a 'ResolverConf'; the
default reads @\/etc\/resolv.conf@.  The setters:

* 'setResolverConfTimeout'
* 'setResolverConfRetries'
* 'setResolverConfSource'
* 'setResolverConfQueryControls'

compose with 'defaultResolvConf' to override individual fields.

Inside a 'withResolver' block the per-RRtype lookup combinators,
such as:

* 'lookupA'
* 'lookupAAAA'
* 'lookupMX'
* 'lookupTXT'
* 'lookupNS'
* 'lookupDS'

each return a list of matching records.  Applications that want
to process the full 'DNSMessage' response can use 'lookupRaw'
or 'lookupRawCtl'.

The 'dnLit' and 'dnLit8' Template-Haskell splices make it
possible to validate a literal domain name at compile time.
The @idna2008@ package provides compatible parsers for Unicode
internationalised domain names (IDNs).

== Module tour

This all-in-one module re-exports almost the entire public API.
Specific topics are covered in:

* Resolver setup and queries — "Net.DNSBase.Resolver",
  "Net.DNSBase.Lookup".
* Domain names — "Net.DNSBase.Domain".
* Resource-record types and the 'RData' wrapper —
  "Net.DNSBase.RR", "Net.DNSBase.RData",
  "Net.DNSBase.RRTYPE", "Net.DNSBase.RRCLASS".
* Address records — "Net.DNSBase.RData.A".
* Name-valued records (CNAME, NS, PTR, etc.) —
  "Net.DNSBase.RData.XNAME".
* Mail and service records (SOA, RP, MX, SRV, NAPTR, etc.) —
  "Net.DNSBase.RData.SOA", "Net.DNSBase.RData.SRV".
* Service-binding records (SVCB, HTTPS) —
  "Net.DNSBase.RData.SVCB".
* DNSSEC (DS, DNSKEY, RRSIG, etc.) and denial of existence
  (NSEC, NSEC3, …) — "Net.DNSBase.RData.Dnssec",
  "Net.DNSBase.RData.NSEC".
* DANE certificate bindings (TLSA, SMIMEA, SSHFP, OPENPGPKEY)
  — "Net.DNSBase.RData.TLSA".
* Other RR types (TXT, CAA, CSYNC, etc.) — the corresponding
  @Net.DNSBase.RData.*@ submodules.
* EDNS options —
  "Net.DNSBase.EDNS", "Net.DNSBase.EDNS.Option" and the
  per-option submodules.
* DNS message structure — "Net.DNSBase.Message".
* Extending the library at runtime —
  "Net.DNSBase.Extensible" (long-form guide),
  "Net.DNSBase.Resolver" (the @register@ and @extend@
  combinators).

-}

module Net.DNSBase
    ( -- * Resolver setup
      -- ** Static resolver configuration
       ResolverConf
     , defaultResolvConf
     , NameserverConf(..)
     , NameserverSpec(..)
      -- ** Resolver seeds
     , ResolvSeed
     , makeResolvSeed
     -- ** Derived resolver objects
     , Resolver(..)
     , withResolver
      -- * Queries
    , Lookup
    , extractAnswers
    , lookupRaw
    , lookupRawCtl
    , lookupAnswers
    , lookupA
    , lookupAAAA
    , lookupMX
    , lookupNS
    , lookupCNAME
    , lookupPTR
    , lookupTXT
    , lookupSOA
    , lookupSRV
    , lookupTLSA
    , lookupHTTPS
      -- * Domain names
    , Domain(..)
    , dnLit
    , decodePresentationDomain
    , dnLit8
    , makeDomain8
    , makeDomain8Str
    , shortBytes
    , wireToDomain
      -- * Resource records, RData, and messages
    , RR(..)
    , DnsTriple(..)
    , RData
    , fromRData
    , RRTYPE
    , RRCLASS
    , DNSMessage
    , DNSError(..)
      -- * Common resource record types
    , T_a(..)
    , T_aaaa(..)
    , T_mx(..)
    , T_srv(..)
    , T_txt(..)
    , T_ptr
    , pattern T_PTR
    , T_https
    , pattern T_HTTPS
      -- * Query and EDNS controls
    , QueryControls(QctlFlags, EdnsEnabled, EdnsDisabled, EdnsUdpSize, EdnsOptionCtl)
    , pattern RDflag
    , pattern ADflag
    , pattern CDflag
    , pattern DOflag
    , setFlagBits
    , clearFlagBits
      -- * Extending the library
    , KnownRData
    , registerRRtype
    , extendRRwithType
    , extendRRwithValue
    , KnownEdnsOption
    , registerEdnsOption
    , extendEdnsOptionWithType
    , extendEdnsOptionWithValue
    , KnownSVCParamValue
    , TypeExtensible(..)
    , ValueExtensible(..)
      -- * Chained-composition opt-in
    , DNSIO
    , runDNSIO
    , liftDNS
      -- * Reference: all re-exported modules
    , module Net.DNSBase.Domain
    , module Net.DNSBase.EDNS
    , module Net.DNSBase.EDNS.OptNum
    , module Net.DNSBase.EDNS.Option
    , module Net.DNSBase.EDNS.Option.ECS
    , module Net.DNSBase.EDNS.Option.EDE
    , module Net.DNSBase.EDNS.Option.NSID
    , module Net.DNSBase.EDNS.Option.Opaque
    , module Net.DNSBase.EDNS.Option.Secalgs
    , module Net.DNSBase.Error
    , module Net.DNSBase.Flags
    , module Net.DNSBase.Lookup
    , module Net.DNSBase.Message
    , module Net.DNSBase.NonEmpty
    , module Net.DNSBase.Opcode
    , module Net.DNSBase.RCODE
    , module Net.DNSBase.RData
    , module Net.DNSBase.RData.A
    , module Net.DNSBase.RData.CAA
    , module Net.DNSBase.RData.CSYNC
    , module Net.DNSBase.Bytes
    , module Net.DNSBase.Present
    , module Net.DNSBase.RData.Dnssec
    , module Net.DNSBase.RData.NSEC
    , module Net.DNSBase.RData.SOA
    , module Net.DNSBase.RData.SRV
    , module Net.DNSBase.RData.SVCB
    , module Net.DNSBase.RData.TLSA
    , module Net.DNSBase.RData.TXT
    , module Net.DNSBase.RData.XNAME
    , module Net.DNSBase.Resolver
    , module Net.DNSBase.RR
    , module Net.DNSBase.RRCLASS
    , module Net.DNSBase.RRTYPE
    , module Net.DNSBase.Secalgs
    , module Net.DNSBase.Text
    ) where

import Net.DNSBase.Bytes
import Net.DNSBase.Domain
import Net.DNSBase.EDNS
import Net.DNSBase.EDNS.OptNum
import Net.DNSBase.EDNS.Option
import Net.DNSBase.EDNS.Option.ECS
import Net.DNSBase.EDNS.Option.EDE
import Net.DNSBase.EDNS.Option.NSID
import Net.DNSBase.EDNS.Option.Opaque
import Net.DNSBase.EDNS.Option.Secalgs
import Net.DNSBase.Error
import Net.DNSBase.Extensible
import Net.DNSBase.Flags
import Net.DNSBase.Lookup
import Net.DNSBase.Message
import Net.DNSBase.NonEmpty
import Net.DNSBase.Opcode
import Net.DNSBase.Present
import Net.DNSBase.RCODE
import Net.DNSBase.RData
import Net.DNSBase.RData.A
import Net.DNSBase.RData.CAA
import Net.DNSBase.RData.CSYNC
import Net.DNSBase.RData.Dnssec
import Net.DNSBase.RData.NSEC
import Net.DNSBase.RData.SOA
import Net.DNSBase.RData.SRV
import Net.DNSBase.RData.SVCB
import Net.DNSBase.RData.TLSA
import Net.DNSBase.RData.TXT
import Net.DNSBase.RData.XNAME
import Net.DNSBase.Resolver
import Net.DNSBase.RR
import Net.DNSBase.RRCLASS
import Net.DNSBase.RRTYPE
import Net.DNSBase.Secalgs
import Net.DNSBase.Text
