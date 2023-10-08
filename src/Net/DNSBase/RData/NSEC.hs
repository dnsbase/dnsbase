{-# LANGUAGE
    CPP
  , MagicHash
  , NegativeLiterals
  , RecordWildCards
  #-}
module Net.DNSBase.RData.NSEC
    ( -- * NSEC, NSEC3, and NSEC Type Bitmap structures
      T_nsec(..)
    , T_nsec3(..)
    , T_nsec3param(..)
    , NsecTypes
    , hasRRtype
    -- * Obsolete NXT structure
    , T_nxt(..)
    , NxtRRtype
    , hasNxtRRtype
    , toNxtTypes
    , module Net.DNSBase.NonEmpty
    ) where

import qualified Data.Primitive.ByteArray as A
import qualified Data.ByteString.Short as SB
import qualified Data.IntMap.Strict as IM
import qualified Data.IntSet as IS
#if MIN_VERSION_base(4,17,0)
import GHC.IsList(IsList(..))
#else
import GHC.Exts(IsList(..))
#endif

import Net.DNSBase.Internal.Util

import Net.DNSBase.Bytes
import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.State
import Net.DNSBase.NonEmpty
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
    } deriving (Typeable, Eq, Show)

instance Ord T_nsec where
    a `compare` b = nsecNext  a `compare` nsecNext  b
                 <> nsecTypes a `compare` nsecTypes b

instance Presentable T_nsec where
    present T_NSEC{..} =
        present          nsecNext
        . presentSpTypes nsecTypes
      where
        presentSpTypes (toList -> types) = flip (foldr presentSp) types

instance KnownRData T_nsec where
    rdType = NSEC
    {-# INLINE rdType #-}
    rdEncode T_NSEC{..} = do
        putSizedBuilder $ mbWireForm nsecNext
        putNsecTypes nsecTypes
    rdDecode _ n = do
        pos0 <- getPosition
        nsecNext  <- getDomainNC
        used <- subtract pos0 <$> getPosition
        nsecTypes <- getNsecTypes (n - used)
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
    } deriving (Typeable, Eq)

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
        presentSpTypes (toList -> types) =
            flip (foldr presentSp) types

instance KnownRData T_nsec3 where
    rdType     = NSEC3
    {-# INLINE rdType #-}
    rdEncode T_NSEC3{..} = do
        putSizedBuilder $
            coerce mbWord8 nsec3Alg
            <> mbWord8 nsec3Flags
            <> mbWord16 nsec3Iters
            <> mbShortByteStringLen8 nsec3Salt
            <> mbShortByteStringLen8 nsec3Next
        putNsecTypes nsec3Types
    rdDecode _ len = do
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
    } deriving (Typeable, Eq, Show)

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
    rdType     = NSEC3PARAM
    {-# INLINE rdType #-}
    rdEncode T_NSEC3PARAM{..} = putSizedBuilder $
        mbWord8 (coerce nsec3paramAlg)
        <> mbWord8 nsec3paramFlags
        <> mbWord16 nsec3paramIters
        <> mbShortByteStringLen8 nsec3paramSalt
    rdDecode _ _ = do
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
    } deriving (Typeable)

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
    rdType     = NXT
    {-# INLINE rdType #-}

    rdEncode T_NXT{..} = putSizedBuilder $
        mbWireForm nxtNext
        <> mbShortByteString (coerce nxtBits)

    cnEncode rd@(T_NXT{nxtNext = d}) =
        rdEncode rd {nxtNext = canonicalise d}

    rdDecode _ len = do
        pos0    <- getPosition
        nxtNext <- getDomain
        used    <- subtract pos0 <$> getPosition
        nxtBits <- getNxtTypes (len - used)
        pure $ RData $ T_NXT{..}

-----------------

-- | Abstract reprenstation of a set of RRTYPEs, optimised for representing
-- NSEC and NSEC3 type bitmaps.
--
-- May legitimately be empty for an NSEC3 empty-non-terminal.  With NSEC,
-- the type bitmap is expected to include at least NSEC.
newtype NsecTypes = NsecTypes (IM.IntMap ShortByteString) deriving Eq

-- | The 'Ord' instance matches wire-form canonical order.
instance Ord NsecTypes where
    a `compare` b = asDnsTextMap a `compare` asDnsTextMap b
      where
        asDnsTextMap :: NsecTypes -> IM.IntMap DnsText
        asDnsTextMap = coerce

instance IsList NsecTypes where
    type Item NsecTypes = RRTYPE
    toList   = nsecTypesToList
    fromList = nsecTypesFromList

instance Show NsecTypes where
    showsPrec p (toList -> tys) = showsP p $
        showString "fromList @NsecTypes "
        . shows' tys

-- | Concatentation va @('<>')@ operator merges the two bitmaps.
instance Semigroup NsecTypes where
    a <> b = coerce $ IM.unionWith mergeBitmaps (coerce a) (coerce b)

-- | Combine two "window" bitmaps by folding the shorter bitmap into a new copy
-- of the longer.
mergeBitmaps :: ShortByteString -> ShortByteString -> ShortByteString
mergeBitmaps win1 win2
    | SB.length win1 >= SB.length win2 = merge win1 win2
    | otherwise                        = merge win2 win1
  where
    merge sb1 sb2@(SB.length -> len2) = baToShortByteString $ A.runByteArray do
        muta <- sbsToMutableByteArray sb1
        let a = sbsToByteArray sb2
        sequence_ [ modifyArray muta i (.|. A.indexByteArray a i)
                  | i <- [0..len2 - 1] ]
        pure muta

-- | Unpack map to list of (window, blocks) pairs
toBitmaps :: NsecTypes -> [(Int, ShortByteString)]
toBitmaps = IM.toList . coerce

-- | Efficient NSEC/NSEC3 type bitmap membership predicate.
hasRRtype :: RRTYPE -> NsecTypes -> Bool
hasRRtype (splitRRtype -> (window, block, bitpos)) (coerce -> im)
    | Just sb <- IM.lookup window im
    , Just byte <- SB.indexMaybe sb block
      = testBit byte bitpos
    | otherwise = False

-- | Convert 'NsecTypes' bitmap to an 'RRTYPE' list
nsecTypesToList :: NsecTypes -> [RRTYPE]
nsecTypesToList = foldr (uncurry windowTypes) [] . toBitmaps
  where
    windowTypes :: Int -> ShortByteString -> [RRTYPE] -> [RRTYPE]
    windowTypes (fromIntegral -> window) = go 0 . SB.unpack
      where
        go :: Word16 -> [Word8] -> [RRTYPE] -> [RRTYPE]
        go !block (w : ws) r
            | z <- countLeadingZeros w
            , z < 8
            , ty <- window .|. block .|. fromIntegral z
              = RRTYPE ty : go block (w `clearBit` (7-z) : ws) r
            | otherwise = go (block + 8) ws r
        go _ _ r = r

-- | Construct the per-window bitmaps from a list of types.
--
nsecTypesFromList :: [RRTYPE] -> NsecTypes
nsecTypesFromList (IS.fromList . map fromIntegral -> tys) =
    -- The list is initially sorted and deduplicated by building a temporary
    -- set, The ordered types from the set are folded into words, which are
    -- then folded into a bitmap by via a mutable unboxed 'Word8' array, whose
    -- underlying storage is finally repackaged as a 'ShortByteString'.
    NsecTypes $ IM.fromAscList $ go Nothing tys
  where
    go bit0 (IS.null -> True)
        | Just off <- bit0 = (off, SB.singleton 0x80) : []
        | otherwise        = []
    go bit0 s@((.&. 0xff00) . IS.findMin -> winbot)
        | bit0 == Just winbot
        , sb <- newSB top (winbot : IS.toList this)
        , slice <- (winbot, sb)
          = slice : go next0 rest
        | sb <- newSB top (IS.toList this)
        , out <- (winbot, sb) : go next0 rest
          = maybe id loner bit0 out
      where
        loner zero = (:) (zero, SB.singleton 0x80)
        winnxt = winbot + 256
        (this, full, rest) = IS.splitMember winnxt s
        top = (IS.findMax this `shiftR` 3) .&. 0x001f
        next0 = bool Nothing (Just winnxt) full

    newSB top = baToShortByteString . mkArray
      where
        mkArray :: [Int] -> ByteArray
        mkArray ts = A.runByteArray do
            a <- A.newByteArray $ top + 1
            A.fillByteArray a 0 (top + 1) 0
            sequence_
                [ modifyArray a byte (`setBit` bitpos)
                | t <- ts
                , let byte = fromIntegral $ (t `shiftR` 3) .&. 0x1f
                , let bitpos = 7 - fromIntegral (t .&. 0x7) ]
            pure a

-- <https://tools.ietf.org/html/rfc4034#section-4.1>
-- Parse a list of NSEC type bitmaps.  The windows are required to be in
-- strictly ascending order.
--
getNsecTypes :: Int -> SGet NsecTypes
getNsecTypes !len = do
    pos0 <- getPosition
    loop (pos0 + len) -1 pos0 $ IM.empty
  where
    loop :: Int -> Int -> Int -> IM.IntMap ShortByteString -> SGet NsecTypes
    loop !end = go
      where
        go :: Int -> Int -> IM.IntMap ShortByteString -> SGet NsecTypes
        go _     !pos0 !m | pos0 == end = pure $ coerce m
        go !off0 !_    !m = do
            off1 <- getOffset
            when (off1 <= off0) do
                failSGet "Non-monotone NSEC window offsets"
            blks <- getBlocks
            pos1 <- getPosition
            go off1 pos1 $ IM.insert off1 blks m

    getOffset = (`shiftL` 8) <$> getInt8

    getBlocks = do
        nblk <- fromIntegral <$> getInt8
        when (nblk > 32) do
           failSGet "Bad NSEC bitmap block count"
        !blks <- getShortNByteString nblk
        case SB.indexMaybe blks (nblk - 1)  of
            Nothing -> failSGet "Empty NSEC bitmap window"
            Just 0  -> failSGet "Empty NSEC bitmap tail block"
            _       -> pure blks

-- | Output the bitmaps.
--
putNsecTypes :: NsecTypes -> SPut s RData
putNsecTypes = mapM_ (uncurry putBitmap) . toBitmaps
  where
    putBitmap offset sb = do
        put8 $ fromIntegral $ offset `shiftR` 8
        putShortByteStringLen8 sb

-- | Split rrtype as window offset, block and bit position.
splitRRtype :: RRTYPE -> (Int, Int, Int)
splitRRtype (fromIntegral -> ty) = (window, block, bitpos)
  where
    !window = ty .&. 0xff00
    !winrel = ty .&. 0x00ff
    !block  = winrel `shiftR` 3
    !bitpos = complement winrel .&. 0x07

-----------------

-- | An RRtype representable in an @NXT@ RR bitmap.
newtype NxtRRtype = RT7 Word16 deriving (Eq, Ord)

instance Bounded NxtRRtype where
    minBound = RT7 0
    maxBound = RT7 127

instance Enum NxtRRtype where
    fromEnum (RT7 t) = fromIntegral t
    toEnum i | i >= 0 && i < 128 = RT7 $ fromIntegral i
             | otherwise = errorWithoutStackTrace "NxtRRtype.toEnum: bad argument"
    pred (RT7 t) | t > 0 = RT7 (t - 1)
                 | otherwise = errorWithoutStackTrace "NxtRRtype.pred: bad argument"
    succ (RT7 t) | t < 127 = RT7 (t + 1)
                 | otherwise = errorWithoutStackTrace "NxtRRtype.succ: bad argument"

instance Show NxtRRtype where
    showsPrec p = showsPrec @RRTYPE p . coerce

instance Presentable NxtRRtype where
    present = present @RRTYPE . coerce

newtype NxtTypes = NxtTypes ShortByteString deriving Eq

-- | The 'Ord' instance matches wire-form canonical order.
instance Ord NxtTypes where
    (NxtTypes a) `compare` (NxtTypes b) = a `compare` b

instance IsNonEmptyList NxtTypes where
    type Item1 NxtTypes = NxtRRtype
    toNonEmptyList   = nxtTypesToNE
    fromNonEmptyList = nxtTypesFromNE

instance Presentable NxtTypes where
    present (toNonEmptyList -> (ty :| tys)) =
        present          ty
        . flip (foldr presentSp) tys

instance Show NxtTypes where
    showsPrec p (toNonEmptyList -> tys) = showsP p $
        showString "fromNonEmptyList @NxtTypes " . shows' tys

-- | Concatentation va @('<>')@ operator merges the two bitmaps.
instance Semigroup NxtTypes where
    a <> b = coerce $ mergeBitmaps (coerce a) (coerce b)

-- | An error if any of input RRtypes are above 127.
toNxtTypes :: NonEmpty RRTYPE -> NxtTypes
toNxtTypes = fromNonEmptyList . fmap (toEnum . fromIntegral)

-- | Reconstruct RRTYPE list from bitmap.
nxtTypesToNE :: NxtTypes -> NonEmpty NxtRRtype
nxtTypesToNE = fromList . go 0 . SB.unpack . coerce
  where
    go :: Word16 -> [Word8] -> [NxtRRtype]
    go !block (w : ws)
        | z <- countLeadingZeros w
        , z < 8
        , ty <- block .|. fromIntegral z
          = RT7 ty : go block (w `clearBit` (7-z) : ws)
        | otherwise = go (block + 8) ws
    go _ _ = []

forceNxt :: NonEmpty NxtRRtype -> [Int]
forceNxt (ty :| tys) =
    fromIntegral NXT : fromEnum ty : map fromEnum tys

-- | Construct the bitmap from a non-empty list of types.
nxtTypesFromNE :: NonEmpty NxtRRtype -> NxtTypes
nxtTypesFromNE (IS.fromList . forceNxt -> s) =
    NxtTypes $ newSB (IS.toList s)
  where
    top = (IS.findMax s `shiftR` 3) .&. 0x001f
    newSB = baToShortByteString . mkArray
      where
        mkArray :: [Int] -> ByteArray
        mkArray ts = A.runByteArray do
            a <- A.newByteArray $ top + 1
            A.fillByteArray a 0 (top + 1) 0
            sequence_
                [ modifyArray a byte (`setBit` bitpos)
                | t <- ts
                , let byte = fromIntegral $ (t `shiftR` 3) .&. 0x1f
                , let bitpos = 7 - fromIntegral (t .&. 0x7) ]
            pure a

-- | Efficient NXT type bitmap membership predicate.
hasNxtRRtype :: RRTYPE -> NxtTypes -> Bool
hasNxtRRtype (splitRRtype -> (window, block, bitpos)) (coerce -> sb)
    | window == 0
    , Just byte <- SB.indexMaybe sb block
      = testBit byte bitpos
    | otherwise = False

getNxtTypes :: Int -> SGet NxtTypes
getNxtTypes !len = do
    when (len < 4 || len > 16) do
       failSGet "Bad NXT bitmap size"
    !blks <- getShortNByteString len
    case SB.indexMaybe blks (len - 1)  of
        Nothing -> failSGet "Empty NXT bitmap" -- not possible
        Just 0  -> failSGet "Empty NSEC bitmap last byte"
        _       -> pure $ coerce blks
