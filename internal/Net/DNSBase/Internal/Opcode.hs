module Net.DNSBase.Internal.Opcode
    ( Opcode
        ( Opcode
        , Query
        , IQuery
        , Status
        , Notify
        , Update
        , DSO
        )
    ) where

import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

-- | The DNS request Opcode from the basic DNS header.  Attempts to construct
-- an 'Opcode' larger than 15 will produce in an error.
--
newtype Opcode = Op_ Word8 deriving (Eq, Ord, Enum, Show)

instance Bounded Opcode where
    minBound = Op_ 0
    maxBound = Op_ 0xf

{-# COMPLETE Opcode #-}
pattern Opcode :: Word8 -> Opcode
pattern Opcode w <- Op_ w where
    Opcode w
        | Op_ w <= maxBound = Op_ w
        | otherwise         = error "Opcode out of range"

-- | The 'Presentable' instance outputs BIND-compatible names.
instance Presentable Opcode where
    present Query    = present @String "QUERY"
    present IQuery   = present @String "IQUERY"
    present Status   = present @String "STATUS"
    present Notify   = present @String "NOTIFY"
    present Update   = present @String "UPDATE"
    present DSO      = present @String "DSO"
    present (Op_ op) = present @String "OPCODE" . present op

------------------------------------------

-- | Query - [RFC1035]
pattern Query        :: Opcode
pattern Query         = Opcode 0

-- | IQuery - [RFC3425]
pattern IQuery       :: Opcode
pattern IQuery        = Opcode 1

-- | Status - [RFC1035]
pattern Status       :: Opcode
pattern Status        = Opcode 2

-- | Opcode 3 is unassigned
--
-- Notify - [RFC1996]
pattern Notify       :: Opcode
pattern Notify        = Opcode 4

-- | Update - [RFC2136]
pattern Update       :: Opcode
pattern Update        = Opcode 5

-- | DSO - [RFC8490] DNS Stateful Operations
pattern DSO          :: Opcode
pattern DSO           = Opcode 6
