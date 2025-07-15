{-# LANGUAGE
    NegativeLiterals
  , RecordWildCards
  #-}
module Net.DNSBase.RData.NSEC
    ( -- * NSEC, NSEC3, and NSEC Type Bitmap structures
      T_nsec(..)
    , T_nsec3(..)
    , T_nsec3param(..)
    , NsecTypes
    , nsecTypesFromList
    , nsecTypesToList
    , hasRRtype
    -- * Obsolete NXT structure
    , T_nxt(..)
    , NxtTypes
    , NxtRRtype
    , toNxtTypes
    , nxtTypesFromNE
    , nxtTypesToNE
    , hasNxtRRtype
    , module Net.DNSBase.NonEmpty
    ) where

import qualified Data.ByteString.Short as SB

import Net.DNSBase.Internal.Util

import Net.DNSBase.Bytes
import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.State
import Net.DNSBase.NonEmpty
import Net.DNSBase.NsecTypes
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE
import Net.DNSBase.Secalgs
import Net.DNSBase.Text

-----------------

-- | [NSEC RDATA](https://datatracker.ietf.org/doc/html/rfc4034#section-4)
-- Used in authenticated denial of existence proofs.
--
-- The next owner name is not subject to
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4),
-- and canonicalises
-- [as-is](https://datatracker.ietf.org/doc/html/rfc6840#section-5.1),
-- [RFC6840](https://datatracker.ietf.org/doc/html/rfc6840#section-5.1)
--
data T_nsec = T_NSEC
    { nsecNext  :: Domain
    , nsecTypes :: NsecTypes
    } deriving (Eq, Show)

instance Ord T_nsec where
    a `compare` b = nsecNext  a `compare` nsecNext  b
                 <> nsecTypes a `compare` nsecTypes b

instance Presentable T_nsec where
    present T_NSEC{..} =
        present          nsecNext
        . presentSpTypes nsecTypes

instance KnownRData T_nsec where
    rdType _ = NSEC
    {-# INLINE rdType #-}
    rdEncode T_NSEC{..} = do
        putSizedBuilder $ mbWireForm nsecNext
        putNsecTypes nsecTypes
    rdDecode _ _ len = do
        pos0 <- getPosition
        nsecNext  <- getDomainNC
        used <- subtract pos0 <$> getPosition
        nsecTypes <- getNsecTypes (len - used)
        pure $ RData T_NSEC{..}

-- | [NSEC3 RDATA](https://tools.ietf.org/html/rfc5155#section-3.2),
-- Used in hashed authenticated denial of existence proofs.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |   Hash Alg.   |     Flags     |          Iterations           |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |  Salt Length  |                     Salt                      /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |  Hash Length  |             Next Hashed Owner Name            /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > /                         Type Bit Maps                         /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- The 'Ord' instance is not canonical.  Canonical ordering requires
-- serialisation to canonical wire form.
--
data T_nsec3 = T_NSEC3
    { nsec3Alg   :: NSEC3HashAlg
    , nsec3Flags :: Word8
    , nsec3Iters :: Word16
    , nsec3Salt  :: ShortByteString
    , nsec3Next  :: ShortByteString
    , nsec3Types :: NsecTypes
    } deriving (Eq)

instance Ord T_nsec3 where
    a `compare` b = nsec3Alg   a `compare`    nsec3Alg   b
                 <> nsec3Flags a `compare`    nsec3Flags b
                 <> nsec3Iters a `compare`    nsec3Iters b
                 <> nsec3Salt  a `dnsTextCmp` nsec3Salt  b
                 <> nsec3Next  a `dnsTextCmp` nsec3Next  b
                 <> nsec3Types a `compare`    nsec3Types b

instance Show T_nsec3 where
    showsPrec p T_NSEC3{..} = showsP p $
        showString "T_NSEC3 "
        . shows'   nsec3Alg   . showChar ' '
        . shows'   nsec3Flags . showChar ' '
        . shows'   nsec3Iters . showChar ' '
        . showSalt nsec3Salt  . showChar ' '
        . showNext nsec3Next  . showChar ' '
        . shows'   nsec3Types
      where
        showNext s = shows @Bytes32 (coerce s)
        showSalt s | SB.null s = showChar '-'
                   | otherwise = shows @Bytes16 (coerce s)

instance Presentable T_nsec3 where
    present T_NSEC3{..} =
        present          nsec3Alg
        . presentSp      nsec3Flags
        . presentSp      nsec3Iters
        . presentSalt    nsec3Salt
        . presentNext    nsec3Next
        . presentSpTypes nsec3Types
      where
        presentNext s = presentSp @Bytes32 (coerce s)
        presentSalt s | SB.null s = presentSp '-'
                      | otherwise = presentSp @Bytes16 (coerce s)

instance KnownRData T_nsec3 where
    rdType _ = NSEC3
    {-# INLINE rdType #-}
    rdEncode T_NSEC3{..} = do
        putSizedBuilder $
            coerce mbWord8 nsec3Alg
            <> mbWord8 nsec3Flags
            <> mbWord16 nsec3Iters
            <> mbShortByteStringLen8 nsec3Salt
            <> mbShortByteStringLen8 nsec3Next
        putNsecTypes nsec3Types
    rdDecode _ _ len = do
        pos0 <- getPosition
        nsec3Alg   <- NSEC3HashAlg <$> get8
        nsec3Flags <- get8
        nsec3Iters <- get16
        nsec3Salt  <- getShortByteStringLen8
        nsec3Next  <- getShortByteStringLen8
        used       <- subtract pos0 <$> getPosition
        nsec3Types <- getNsecTypes (len - used)
        pure $ RData T_NSEC3{..}

-- | [NSEC3PARAM RDATA](https://tools.ietf.org/html/rfc5155#section-4.2).
-- DNSSEC hashed denial of existence parameters.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |   Hash Alg.   |     Flags     |          Iterations           |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |  Salt Length  |                     Salt                      /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- (Editorial comment, the salt and iteration count were largely
-- a bad idea in retrospect, and best practice for zone signers
-- is to set the salt empty and the iteration count to zero).
--
data T_nsec3param = T_NSEC3PARAM
    { nsec3paramAlg   :: NSEC3HashAlg
    , nsec3paramFlags :: Word8
    , nsec3paramIters :: Word16
    , nsec3paramSalt  :: ShortByteString
    } deriving (Eq, Show)

instance Ord T_nsec3param where
    compare a b =
       comparing nsec3paramAlg a b
       <> comparing nsec3paramFlags a b
       <> comparing nsec3paramIters a b
       <> dnsTextCmp (nsec3paramSalt  a) (nsec3paramSalt  b)

instance Presentable T_nsec3param where
    present T_NSEC3PARAM{..} =
        present       nsec3paramAlg
        . presentSp   nsec3paramFlags
        . presentSp   nsec3paramIters
        . presentSalt nsec3paramSalt
      where
        presentSalt s | SB.null s = presentSp '-'
                      | otherwise = presentSp @Bytes16 (coerce s)

instance KnownRData T_nsec3param where
    rdType _ = NSEC3PARAM
    {-# INLINE rdType #-}
    rdEncode T_NSEC3PARAM{..} = putSizedBuilder $
        mbWord8 (coerce nsec3paramAlg)
        <> mbWord8 nsec3paramFlags
        <> mbWord16 nsec3paramIters
        <> mbShortByteStringLen8 nsec3paramSalt
    rdDecode _ _ = const do
        nsec3paramAlg   <- NSEC3HashAlg <$> get8
        nsec3paramFlags <- get8
        nsec3paramIters <- get16
        nsec3paramSalt  <- getShortByteStringLen8
        pure $ RData T_NSEC3PARAM{..}

-- | [NXT RDATA](https://www.rfc-editor.org/rfc/rfc2535.html#section-5.2).
-- Obsolete predecessor of @NSEC@.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                  next domain name                             /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                    type bit map                               /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
-- The domain name is subject to name compression only when decoding:
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4),
-- and canonicalise to
-- [lower case](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- Equality and comparison are case-insensitive.
--
data T_nxt = T_NXT
    { nxtNext :: Domain
    , nxtBits :: NxtTypes
    }

instance Show T_nxt where
    showsPrec p T_NXT{..} = showsP p $
        showString "T_NXT "
        . shows' nxtNext . showChar ' '
        . shows' nxtBits

instance Eq T_nxt where
    a == b = nxtNext  a `equalWireHost` nxtNext  b
          && nxtBits  a ==              nxtBits  b

instance Ord T_nxt where
    a `compare` b = nxtNext a `compareWireHost` nxtNext b
                 <> nxtBits a `compare`         nxtBits b

instance Presentable T_nxt where
    present T_NXT{..} =
        present nxtNext
        . presentSp nxtBits

instance KnownRData T_nxt where
    rdType _ = NXT
    {-# INLINE rdType #-}

    rdEncode T_NXT{..} = putSizedBuilder $
        mbWireForm nxtNext
        <> mbShortByteString (coerce nxtBits)

    cnEncode rd@(T_NXT{nxtNext = d}) =
        rdEncode rd {nxtNext = canonicalise d}

    rdDecode _ _ len = do
        pos0    <- getPosition
        nxtNext <- getDomain
        used    <- subtract pos0 <$> getPosition
        nxtBits <- getNxtTypes (len - used)
        pure $ RData $ T_NXT{..}
