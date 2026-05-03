{-|
Module      : Net.DNSBase.Present
Description : Zone-file presentation form: the 'Presentable' class and helpers
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 'Presentable' typeclass renders DNS data into the conventional zone-file
textual form
([RFC 1035 section 5](https://datatracker.ietf.org/doc/html/rfc1035#section-5),
with later refinements).  Instances produce 'Data.ByteString.Builder.Builder'
fragments, which are stitched together by the small combinator set
('presentSp', 'presentCharSep', 'presentLn', and friends) for separators and
line breaks.  'presentString' and 'presentStrict' run the builder to a 'String'
or strict 'Data.ByteString.ByteString' for final output; 'putBuilder' writes a
builder to stdout.

The 'Epoch64' newtype renders a 64-bit absolute time as the
RFC 4034 14-digit @YYYYMMDDHHmmSS@ string used in RRSIG
timestamps.
-}

module Net.DNSBase.Present
    ( Presentable(..)
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
    -- ** Build directly to a 'String' or 'Data.ByteString.ByteString'
    , presentString
    , presentStrict
    -- ** Re-exported from "Data.ByteString.Builder"
    , Builder
    , hPutBuilder
    -- *** 'hPutBuilder' specialised to @stdout@
    , putBuilder
    ) where

import Net.DNSBase.Internal.Present
