module Net.DNSBase.EDNS.Option
    ( -- * Generic EDNS option class
     EdnsOption(..)
    , SomeOption(..)
    , OptEncode
    , fromOption
    , monoOption
    , optionCode
    , putOption
    -- * Resolver EDNS option controls
    , OptionCtl
    , optCtlSet
    , optCtlAdd
    , emptyOptionCtl
    , applyOptionCtl
    ) where

import Net.DNSBase.EDNS.Internal.Option
