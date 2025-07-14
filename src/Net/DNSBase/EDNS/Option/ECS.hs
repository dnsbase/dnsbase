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

-- | Client subnet [RFC7871, Section 6](https://tools.ietf.org/html/rfc7871#section-6).
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
-- The address is masked and truncated when encoding queries.  The
-- address is zero-padded when decoding.  Invalid input encodings
-- result in an 'OD_ECSgeneric' value instead.
--
-- The family value is @1@ for IPv4 and @2@ for IPv6.  This is implicit in the
-- IP address type of the decoded structure,
--
data O_ecs = O_ECS Word8 Word8 IP deriving (Eq, Show)

instance Presentable O_ecs where
    present (O_ECS srcbits scopebits ip) =
        present srcbits
        . presentSp scopebits
        . presentSp ip

instance EdnsOption O_ecs where
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
    optDecode _ = getECS

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
       -> SGet SomeOption
getECS n = do
    ecs_family <- get16
    ecs_source <- get8
    ecs_scope  <- get8
    case ecs_family of
        1 -> do
            ecs_addr <- getIPv4Net (n - 4)
            return $ SomeOption $ O_ECS ecs_source ecs_scope (IPv4 ecs_addr)
        2 -> do
            ecs_addr <- getIPv6Net (n - 4)
            return $ SomeOption $ O_ECS ecs_source ecs_scope (IPv6 ecs_addr)
        f -> failSGet $ "unsupported ECS family " ++ show f
        -- XXX : consider using alternate constructor instead of failure
