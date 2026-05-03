{-|
Module      : Net.DNSBase.Bytes
Description : Newtype wrappers tagging byte strings with a presentation encoding
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

Three identical 'ShortByteString' wrappers that differ only in
their 'Net.DNSBase.Present.Presentable' instance: 'Bytes16'
renders as hex, 'Bytes32' as base32, 'Bytes64' as base64.  Used
inside RR data types to tag a field with the encoding the
zone-file syntax expects, so that a single
'Net.DNSBase.Present.present' call produces the conventional
representation without each call site having to pick the encoder.
-}

module Net.DNSBase.Bytes
    ( -- * Short ByteStrings elements that are presented encoded
      Bytes16(..)
    , Bytes32(..)
    , Bytes64(..)
    ) where

import Net.DNSBase.Internal.Bytes
