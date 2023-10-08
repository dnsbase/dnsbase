module Net.DNSBase.Present
    (
      Presentable(..)
    -- ** Builder combinators
    , presentByte
    , presentCharSep
    , presentCharSepLn
    , presentLn
    , presentSep
    , presentSepLn
    , presentSp
    , presentSpLn
    -- *** Newtype to present 64-bit epoch times.
    , Epoch64(..)
    -- ** Build directly to a 'String' or 'ByteString'
    , presentString
    , presentStrict
    -- ** Re-exported from "Data.ByteString.Builder"
    , Builder
    , hPutBuilder
    -- *** 'hPutBuilder' specialised to 'stdout'
    , putBuilder
    ) where

import Net.DNSBase.Internal.Present
