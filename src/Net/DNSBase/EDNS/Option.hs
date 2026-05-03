{-|
Module      : Net.DNSBase.EDNS.Option
Description : EDNS option typeclass, existential wrapper, and resolver controls
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 'KnownEdnsOption' typeclass binds a concrete option type to its
16-bit code; the existential 'EdnsOption' wrapper lets an
option list hold a heterogeneous mix.  Unknown option codes
decode as 'Net.DNSBase.EDNS.Option.Opaque.OpaqueOption' from
"Net.DNSBase.EDNS.Option.Opaque", preserving the raw bytes for
inspection or pass-through.  Applications register new typed
options at runtime via 'Net.DNSBase.Resolver.registerEdnsOption';
options whose codec admits typed or value-driven extensions
(e.g. 'Net.DNSBase.EDNS.Option.EDE.O_ede') also accept
'Net.DNSBase.Resolver.extendEdnsOptionWithType' /
'Net.DNSBase.Resolver.extendEdnsOptionWithValue'.  See
"Net.DNSBase.Extensible" for the full guide.

The 'OptionCtl' machinery, with 'optCtlSet' / 'optCtlAdd', is
the building block 'Net.DNSBase.Resolver.QueryControls' uses for per-call EDNS
option list tweaks — see 'Net.DNSBase.Resolver.EdnsOptionCtl'.
-}

module Net.DNSBase.EDNS.Option
    ( -- * Generic EDNS option class
     KnownEdnsOption(..)
    , EdnsOption(..)
    , fromOption
    , monoOption
    , optionCode
    , putOption
    -- * Extensibility
    , OptionCodec
    -- * Resolver EDNS option controls
    , OptionCtl
    , optCtlSet
    , optCtlAdd
    , emptyOptionCtl
    , applyOptionCtl
    ) where

import Net.DNSBase.EDNS.Internal.Option
