module Net.DNSBase.EDNS.Internal.Option.Opaque
    ( OpaqueOption(..)
    , opaqueOption
    )
    where

import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.EDNS.Internal.OptNum
import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.Bytes
import Net.DNSBase.Internal.Nat16
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

-- | Unrecognized EDNS Option whose contents are treated as an opaque octet-string
-- and are left unparsed. The OPTION-CODE is encoded as a type-level natural, so
-- opaque options with different option code values are of different types.
type OpaqueOption :: Nat -> Type
data OpaqueOption n = OpaqueOption ShortByteString

deriving instance Eq (OpaqueOption n)

instance Nat16 n => Show (OpaqueOption n) where
    showsPrec p (OpaqueOption bs) = showsP p $
        showString "OpaqueOption @" . shows (natToWord16 n) . showChar ' '
        . shows @Bytes16 (coerce bs)

instance Presentable (OpaqueOption n) where
    present = \ (OpaqueOption bs) -> present @Bytes16 (coerce bs)

instance Nat16 n => EdnsOption (OpaqueOption n) where
    optNum _ = OptNum $ natToWord16 n
    {-# INLINE optNum #-}
    optPres _ = present "OPT" . present (natToWord16 n)
    optEncode (OpaqueOption bs) = putShortByteString $ coerce bs
    optDecode _ = SomeOption . OpaqueOption @n <.> getShortNByteString

-- | Create opaque option from its opcode and Bytes16 value
opaqueOption :: Word16 -> ShortByteString -> SomeOption
opaqueOption w bs = withNat16 w go
  where
    go :: forall (n :: Nat) -> Nat16 n => SomeOption
    go n = SomeOption $ OpaqueOption @n bs
