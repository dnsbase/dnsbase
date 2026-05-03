{-|
Module      : Net.DNSBase.EDNS.Option.ECS
Description : EDNS Client Subnet option (RFC 7871)
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The Client Subnet EDNS option lets a recursive resolver forward
a prefix of the original client's address to an authoritative
server, so that authority-side answers (CDNs and similar) can
be tailored to the client's network location.  The
specification, including privacy considerations, is
[RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871).
-}

module Net.DNSBase.EDNS.Option.ECS
    ( O_ecs(..)
    ) where

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.EDNS.Internal.OptNum
import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Encode.Internal.Metric
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

-- | The Client Subnet EDNS option
-- ([RFC 7871 section 6](https://tools.ietf.org/html/rfc7871#section-6))
-- — three fields: a source prefix length, a scope prefix length,
-- and a (possibly truncated) IP address whose 16-bit @FAMILY@
-- field is implicit in the constructor's 'IP' value (@1@ for
-- 'IPv4', @2@ for 'IPv6').
--
-- >            +0 (MSB)                            +1 (LSB)
-- >  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- >  |                          OPTION-CODE                          |
-- >  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- >  |                         OPTION-LENGTH                         |
-- >  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- >  |                            FAMILY                             |
-- >  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- >  |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |
-- >  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
-- >  |                           ADDRESS...                          /
-- >  +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
--
-- The address is masked and truncated to the source prefix length
-- on encode and zero-padded on decode.  A @FAMILY@ value other
-- than 1 or 2 fails the decoder (a future revision may decode
-- such values as an opaque option instead).
data O_ecs = O_ECS Word8 Word8 IP deriving (Eq, Show)

instance Presentable O_ecs where
    present (O_ECS srcbits scopebits ip) =
        present srcbits
        . presentSp scopebits
        . presentSp ip

instance KnownEdnsOption O_ecs where
    optNum _ = ECS
    {-# INLINE optNum #-}
    optEncode (O_ECS srcbits scopebits ip) = case ip of
        IPv4 ip4 -> do
                    -- XXX: More precise error?
                    when (srcbits < 0 || srcbits > 32) $
                        failWith CantEncode
                    let (!q, !r) = (srcbits + 7) `quotRem` 8
                        !w = fromIPv4w ip4
                    putSizedBuilder $
                        mbWord16 1
                        <> mbWord8 srcbits
                        <> mbWord8 scopebits
                        <> encWord w q r
        IPv6 ip6 -> do
                    -- XXX: More precise error?
                    when (srcbits < 0 || srcbits > 128) $
                        failWith CantEncode
                    let (!q, !r) = (srcbits + 7) `quotRem` 8
                        (!w0, !w1, !w2, !w3) = fromIPv6w ip6
                    putSizedBuilder $
                        mbWord16 2
                        <> mbWord8 srcbits
                        <> mbWord8 scopebits
                        <> encWord w0 q r
                        <> encWord w1 (q - 4) r
                        <> encWord w2 (q - 8) r
                        <> encWord w3 (q - 12) r
    optDecode _ _ = getECS

encWord :: Word32 -> Word8 -> Word8 -> SizedBuilder
encWord !w !q !r = case min 4 q of
    4 -> mbWord32 (w .&. mask)
    3 -> (mbWord16 . fromIntegral) (w `unsafeShiftR` 16) <>
         (mbWord8  . fromIntegral) ((w `unsafeShiftR` 8) .&. mask)
    2 -> (mbWord16 . fromIntegral) ((w `unsafeShiftR` 16) .&. mask)
    1 -> (mbWord8  . fromIntegral) ((w `unsafeShiftR` 24) .&. mask)
    _ -> mempty
  where
    mask | q <= 4
         , s <- fromEnum $ 7 - r
         , s > 0    = (0xffff_ffff `unsafeShiftR` s) `unsafeShiftL` s
         | otherwise = 0xffff_ffff

-- | Decode an EDNS Client Subnet (ECS) option according to the provided
-- OPTION-LENGTH Parameter to determine how many bytes the address has been
-- truncated to.
--
-- Values of the FAMILY field other than 1 (IPv4) or 2 (IPv6) are rejected
-- and cause the decoder to fail.
getECS :: Int -- ^ OPTION-LENGTH field
       -> SGet EdnsOption
getECS n = do
    ecs_family <- get16
    ecs_source <- get8
    ecs_scope  <- get8
    case ecs_family of
        1 -> do
            ecs_addr <- getIPv4Net (n - 4)
            return $ EdnsOption $ O_ECS ecs_source ecs_scope (IPv4 ecs_addr)
        2 -> do
            ecs_addr <- getIPv6Net (n - 4)
            return $ EdnsOption $ O_ECS ecs_source ecs_scope (IPv6 ecs_addr)
        f -> failSGet $ "unsupported ECS family " ++ show f
        -- XXX : consider using alternate constructor instead of failure
