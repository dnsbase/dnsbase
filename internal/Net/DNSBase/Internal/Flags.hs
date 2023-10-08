module Net.DNSBase.Internal.Flags
    ( DNSFlags
        ( QRflag
        , AAflag
        , TCflag
        , RDflag
        , RAflag
        , Zflag
        , ADflag
        , CDflag
        , DOflag
        )
    -- * DNS flag construction and inspection
    , basicFlags
    , extendFlags
    , extendedFlags
    , extractOpcode
    , extractRCODE
    , hasAllFlags
    , hasAnyFlags
    , makeDNSFlags
    , maskDNSFlags
    , complementDNSFlags
    -- * DNS flag query control support
    , FlagOps
    , setFlagBits
    , clearFlagBits
    , resetFlagBits
    , emptyFlagOps
    , applyFlagOps
    , defaultQueryFlags
    ) where

import Net.DNSBase.Internal.RCODE
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Opcode
import Net.DNSBase.Internal.Util


-- | The basic DNS header flags word is a mixture of flag bits and numbers,
-- <https://tools.ietf.org/html/rfc2535#section-6.1>.
--
--                                  1  1  1  1  1  1
--    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The RFC numbering of the bits looks little-endian, but we represent the
-- basic flags as a big-ending 16 bit word with @QR@ in the high (15th) bit.
-- This gives correct values for the @Opcode@ and @RCODE@, whose MSB bits are
-- on the left (the @Opcode@ and @RCODE@ values are big-endian).
--
-- Therefore, when ordering the bits for presentation, we output the stored
-- bits in MSB-to-LSB order, and also do the same with the extended bits
-- below. This matches the left-to-right order from the RFCs.
--
-- The basic header flags are extended with 16 more bits in the low-order
-- second word (bytes 3+4) of the TTL field of the EDNS(0) OPT pseudo-RR:
-- <https://tools.ietf.org/html/rfc6891#section-6.1.3>.
--
--    1  1  1  1  2  2  2  2  2  2  2  2  2  2  3  3
--    6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |DO|                    Z                       |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The DNSFlags type combines both the extended and basic flags into a 32-bit
-- word, with the extended flags in the MSB 16-bits.  The bits corresponding
-- to the @Opcode@ and @RCODE@ cannot be set and are always zero.
--
-- Additional bits may be registered from time to time, see the
-- [IANA DNS Header Flags](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12)
-- and
-- [IANA EDNS Header Flags](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13>)
-- registries.
--
-- Flags can be combined via the 'Monoid' instance, or set explicitly via
-- 'makeDNSFlags'.
--
-- The integral values of the flags are user-visible, users manipulating the
-- flags directly, rather than exclusively via the provided pattern synonyms
-- need to be mindful of the representation.
--
newtype DNSFlags = DNSFlags Word32 deriving (Eq, Show)

instance Semigroup DNSFlags where
    (DNSFlags a) <> (DNSFlags b) = DNSFlags $ (a .|. b) .&. validBits

instance Monoid DNSFlags where
    mempty = DNSFlags 0

-- | Output the names of the flags set.  If none set, outputs a dash: @-@.
instance Presentable DNSFlags where
    present (DNSFlags fl) k =
        case filter (testBit fl . bitpos) [0..31] of
            []     -> present '-' k
            (v:vs) -> bitName v $ foldr ($) k [bitNameSp v' | v' <- vs]
      where
        bitpos n = (15 - n) `mod` 32
        bitNameSp n = present ' ' . bitName n
        bitName n = case DNSFlags $ shiftL 1 (bitpos n) of
            QRflag -> p "qr"
            AAflag -> p "aa"
            TCflag -> p "tc"
            RDflag -> p "rd"
            RAflag -> p "ra"
            Zflag  -> p "z"
            ADflag -> p "ad"
            CDflag -> p "cd"
            DOflag -> p "do"
            _      -> p "bit" . present n
        p = present @String

------------------------------------------

-- | Reserve (i.e. mask out) 4-bit segments corresponding to the @Opcode@
-- and @RCODE@ fields of a basic DNS header. High 16 bits from EDNS are
-- all included, if present.
validBits :: Word32
validBits = complement 0b0111_1000_0000_1111

extractRCODE :: Word16 -> RCODE
extractRCODE bits = RCODE $ bits .&. 0b1111

extractOpcode :: Word16 -> Opcode
extractOpcode bits = Opcode . fromIntegral $ (bits `shiftR` 11) .&. 0b1111

-- | Compute a combined basic DNS header flags word
basicFlags :: Opcode    -- ^ Opcode
           -> RCODE     -- ^ Extended (12-bit) RCODE
           -> DNSFlags  -- ^ Basic and EDNS flags
           -> Word16    -- ^ Flags field for basic DNS header
{-# INLINE basicFlags #-}
basicFlags (Opcode op) (RCODE rc) (DNSFlags fl) =
    opbits .|. flbits .|. rcbits
  where
    opbits = (fromIntegral op .&. 0xF) `shiftL` 11
    rcbits = (fromIntegral rc .&. 0xF)
    flbits = (fromIntegral fl .&. 0xFFFF)

-- | Compute the EDNS flags
extendedFlags :: DNSFlags -- ^ DNSFlags bits
              -> Word16   -- ^ Corresponding EDNS(0) flags word
{-# INLINE extendedFlags #-}
extendedFlags (DNSFlags fl) = fromIntegral $ fl `unsafeShiftR` 16 .&. 0xFFFF

-- | Test whether all flags in the first argument are set in the second.
hasAllFlags :: DNSFlags -> DNSFlags -> Bool
hasAllFlags wanted have = maskDNSFlags wanted have == wanted

-- | Test whether any flags in the first argument are set in the second.
hasAnyFlags :: DNSFlags -> DNSFlags -> Bool
hasAnyFlags wanted have = maskDNSFlags wanted have /= mempty

-- | Construct flags from an explicit integral bit field.  The basic DNS bits
-- are taken from the least-significant 16 bits of the input, and the EDNS
-- flags from the adjacent 16 bits of the input.  Reserved and out of range
-- bits are silently ignored.
makeDNSFlags :: Integral a => a -> DNSFlags
makeDNSFlags fl = DNSFlags $ fromIntegral fl .&. validBits
{-# INLINE makeDNSFlags #-}

-- | Apply bitwise @and@ to two DNSFlags values.
maskDNSFlags :: DNSFlags -> DNSFlags -> DNSFlags
maskDNSFlags (DNSFlags a) (DNSFlags b) = DNSFlags $ a .&. b

-- | Return the flags /not set/.
complementDNSFlags :: DNSFlags -> DNSFlags
complementDNSFlags (DNSFlags fl) = DNSFlags $ complement fl .&. validBits

-- | Combine basic header flags (low 16 bits)
--     with EDNS extended flags (high 16 bits)
extendFlags :: DNSFlags -> Word16 -> DNSFlags
extendFlags (DNSFlags lo) hi =
    DNSFlags $ (fromIntegral hi `shiftL` 16) .|. (lo .&. 0xFFFF)

------------------------------------------

-- | QR (Query or Response) - Clear in queries, set in responses.
pattern QRflag :: DNSFlags
pattern QRflag  = DNSFlags 0x8000
-- | AA (Authoritative answer) - This bit is valid in responses, and specifies
-- that the responding name server is an authority for the domain name in
-- question section.
pattern AAflag :: DNSFlags
pattern AAflag  = DNSFlags 0x0400
-- | TC (Truncated Response) - Specifies that the response was truncated due
-- to length greater than that permitted on the transmission channel.
pattern TCflag :: DNSFlags
pattern TCflag  = DNSFlags 0x0200
-- | RD (Recursion Desired) - This bit may be set in a query and is copied into
-- the response.  If RD is set, it directs the name server to pursue the query
-- recursively.  Authoritative servers may refuse recursive queries, and,
-- conversely, iterative resolvers may refuse non-recursive queries.
pattern RDflag :: DNSFlags
pattern RDflag  = DNSFlags 0x0100
-- | RA (Recursion available) - This is a response bit, and denotes whether
-- recursive query support is available in the name server.
pattern RAflag :: DNSFlags
pattern RAflag  = DNSFlags 0x0080
-- | Z (Reserved, zero until future specification)
pattern  Zflag :: DNSFlags
pattern  Zflag  = DNSFlags 0x0040
-- | AD (Authentic Data) bit - RFC4035, Section 3.2.3.
-- See also [RFC6840, Section 5.8](https://tools.ietf.org/html/rfc6840#section-5.8)
pattern ADflag :: DNSFlags
pattern ADflag  = DNSFlags 0x0020
-- | CD (Checking Disabled) bit - RFC4035, Section 3.2.2.
pattern CDflag :: DNSFlags
pattern CDflag  = DNSFlags 0x0010
-- | DO (DNSSEC OK) bit - RFC3225, Section 3, RFC6891, Section-6.1.4.
pattern DOflag :: DNSFlags
pattern DOflag  = DNSFlags 0x80000000

----------------------------------------

data FlagOps =
     FlagOps { clearBits :: DNSFlags
             , setBits   :: DNSFlags
             } deriving (Eq, Show)

setFlagBits :: DNSFlags -> FlagOps -> FlagOps
setFlagBits (DNSFlags fl) (FlagOps (DNSFlags fl0) (DNSFlags fl1)) =
    FlagOps (DNSFlags (fl0 .&. complement fl))
            (DNSFlags (fl1 .|. fl))

clearFlagBits :: DNSFlags -> FlagOps -> FlagOps
clearFlagBits (DNSFlags fl) (FlagOps (DNSFlags fl0) (DNSFlags fl1)) =
    FlagOps (DNSFlags (fl0 .|. fl))
            (DNSFlags (fl1 .&. complement fl))

resetFlagBits :: DNSFlags -> FlagOps -> FlagOps
resetFlagBits (DNSFlags fl) (FlagOps (DNSFlags fl0) (DNSFlags fl1)) =
    FlagOps (DNSFlags (fl0 .&. complement fl))
            (DNSFlags (fl1 .&. complement fl))

emptyFlagOps :: FlagOps
emptyFlagOps = FlagOps (DNSFlags 0x0) (DNSFlags 0x0)

applyFlagOps :: FlagOps -> DNSFlags -> DNSFlags
applyFlagOps (FlagOps (DNSFlags fl0) (DNSFlags fl1)) (DNSFlags fl) =
    DNSFlags (fl .&. (complement (fl0 .&. validBits)) .|. (fl1 .&. validBits))

-- | Default query flags include just the 'RDflag'.
defaultQueryFlags :: DNSFlags
defaultQueryFlags = RDflag
