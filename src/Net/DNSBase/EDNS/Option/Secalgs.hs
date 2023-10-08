-- |
-- Module      : Net.DNSBase.EDNS.Option.Secalgs
-- Description : EDNS signalling of DNSSEC algorithms understood by the client
-- Copyright   : (c) Viktor Dukhovni, 2020
-- License     : BSD-3
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : experimental
-- Portability : GHC >= 8.0
--
-- RFC 6975 specifies a way for validating end-system resolvers to signal
-- to a server which digital signature and hash algorithms they support.
-- This signalling does not alter server behaviour, rather it just provides
-- a means to server operators to collect data on client algorithm support
-- to assist in planning future algorithm selection.
--
-- The format of the associated EDNS options is defined in
-- [RFC6975, Section 3](https://tools.ietf.org/html/rfc6975#section-3)
-- as follows:
--
-- >  0                       8                      16
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  |                  OPTION-CODE                  |
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  |                  LIST-LENGTH                  |
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- >  |       ALG-CODE        |        ...            /
-- >  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- i.e. a 16-bit count, followed by a sequence of 8-bit algorithm numbers.
--
-- The use of SHA-1 in NSEC3 is essentially light-weight obfuscation to
-- discourage casual zone walking. Implementation and adoption of successor
-- algorithms seems unlikely, and would in also be most counter-productive.
-- Therefore, while the N3U option is defined here, it is best left unused.
-- As of February 2020, the IANA registry of
-- [NSEC3 hash algorithms](https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml#dnssec-nsec3-parameters-3)
-- lists just SHA-1:
--
--  +---------+---------------+-----------+
--  | Value   | Description   | Reference |
--  +=========+===============+===========+
--  | 0       | Reserved      | [RFC5155] |
--  +---------+---------------+-----------+
--  | 1       | SHA-1         | [RFC5155] |
--  +---------+---------------+-----------+
--  | 2-255   | Unassigned    |           |
--  +---------+---------------+-----------+
--
-- This is not expected to change.
--
module Net.DNSBase.EDNS.Option.Secalgs
    ( O_dau(..)
    , O_dhu(..)
    , O_n3u(..)
    ) where

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.EDNS.Internal.OptNum
import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Encode.Internal.Metric
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

import Net.DNSBase.Secalgs

-- | DNSSEC Algorithm Understood (RFC6975).
newtype O_dau = O_DAU [DNSKEYAlg] deriving (Typeable, Eq, Show)
-- | DS Hash Understood (RFC6975).
newtype O_dhu = O_DHU [DSHashAlg] deriving (Typeable, Eq, Show)
-- | NSEC3 Hash Understood (RFC6975).
newtype O_n3u = O_N3U [NSEC3HashAlg] deriving (Typeable, Eq, Show)

instance Presentable O_dau where
    present (O_DAU val) = case val of
        []     -> present '-'
        (v:vs) -> present v . flip (foldr presentSp) vs

instance Presentable O_dhu where
    present (O_DHU val) = case val of
        []     -> present '-'
        (v:vs) -> present v . flip (foldr presentSp) vs

instance Presentable O_n3u where
    present (O_N3U val) = case val of
        []     -> present '-'
        (v:vs) -> present v . flip (foldr presentSp) vs

instance EdnsOption O_dau where
    optNum     = DAU
    {-# INLINE optNum #-}
    optEncode  = putSizedBuilder . coerce foldDAU
      where
        foldDAU :: [DNSKEYAlg] -> SizedBuilder
        foldDAU = foldMap mbDAU
        mbDAU :: DNSKEYAlg -> SizedBuilder
        mbDAU = coerce mbWord8
    optDecode len =
        SomeOption . O_DAU <$> getFixedWidthSequence 1 (coerce <$> get8) len

instance EdnsOption O_dhu where
    optNum     = DHU
    {-# INLINE optNum #-}
    optEncode  = putSizedBuilder . coerce foldDHU
      where
        foldDHU :: [DSHashAlg] -> SizedBuilder
        foldDHU = foldMap mbDHU
        mbDHU :: DSHashAlg -> SizedBuilder
        mbDHU = coerce mbWord8
    optDecode len =
        SomeOption . O_DHU <$> getFixedWidthSequence 1 (coerce <$> get8) len

instance EdnsOption O_n3u where
    optNum     = N3U
    {-# INLINE optNum #-}
    optEncode  = putSizedBuilder . coerce foldN3U
      where
        foldN3U :: [NSEC3HashAlg] -> SizedBuilder
        foldN3U = foldMap mbN3U
        mbN3U :: NSEC3HashAlg -> SizedBuilder
        mbN3U = coerce mbWord8
    optDecode len =
        SomeOption . O_N3U <$> getFixedWidthSequence 1 (coerce <$> get8) len
