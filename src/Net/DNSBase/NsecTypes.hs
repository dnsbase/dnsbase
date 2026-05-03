{-|
Module      : Net.DNSBase.NsecTypes
Description : Type-bitmap structures for NSEC, NSEC3, CSYNC, and legacy NXT
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The packed bitmap used to list which RR types are present at
(or relevant to) the owner name.  'NsecTypes' is the
window-based encoding from
[RFC 4034 section 4.1.2](https://datatracker.ietf.org/doc/html/rfc4034#section-4.1.2),
used by 'Net.DNSBase.RData.NSEC.T_nsec',
'Net.DNSBase.RData.NSEC.T_nsec3', and
'Net.DNSBase.RData.CSYNC.T_csync' to carry an arbitrary set of
'RRTYPE' codepoints in a compact form.  'NxtTypes' is the legacy
single-window encoding used by the obsolete @NXT@ record, which
restricts types to the first 128 codepoints.

'NsecTypes' is an instance of 'IsList' with @'Item' 'NsecTypes' =
'RRTYPE'@, so construction is via @'fromList' xs@ from
"GHC.IsList" (or @['A', 'AAAA', ...]@ under @OverloadedLists@,
via the associated 'RRTYPE' pattern synonyms) and enumeration
is via 'toList'.  The input list is deduplicated and reordered
into wire-form canonical order; an empty input produces the empty
bitmap.  'hasRRtype' is the efficient membership predicate used by
DNSSEC validators.

==== __Example__

> ghci> import qualified GHC.IsList as IL (fromList, toList)
> ghci> tys = IL.fromList @NsecTypes [MX, A, AAAA, A]
> ghci> tys
> fromList @NsecTypes [1,15,28]
> ghci> IL.toList tys
> [1,15,28]
> ghci> hasRRtype AAAA tys
> True
> ghci> hasRRtype NS tys
> False
-}
{-# LANGUAGE NegativeLiterals #-}

module Net.DNSBase.NsecTypes
    ( -- * NSEC/NSEC3/CSYNC Type Bitmap structure
      NsecTypes
    , nsecTypesFromList
    , nsecTypesToList
    , getNsecTypes
    , putNsecTypes
    , hasRRtype
    -- * Legacy type bitmap in NXT records
    , NxtTypes(..)
    , NxtRRtype
    , toNxtTypes
    , nxtTypesFromNE
    , nxtTypesToNE
    , getNxtTypes
    , hasNxtRRtype
    --
    , module Net.DNSBase.NonEmpty
    ) where

import qualified Data.Primitive.ByteArray as A
import qualified Data.ByteString.Short as SB
import qualified Data.IntMap.Strict as IM
import qualified Data.IntSet as IS
import GHC.IsList(IsList(..))

import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.State
import Net.DNSBase.NonEmpty
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE
import Net.DNSBase.Text

-----------------

-- | Abstract representation of a set of 'RRTYPE' codepoints,
-- stored as the window-based wire-format bitmap from RFC 4034
-- section 4.1.2.  Used by 'Net.DNSBase.RData.NSEC.T_nsec',
-- 'Net.DNSBase.RData.NSEC.T_nsec3', and
-- 'Net.DNSBase.RData.CSYNC.T_csync' to carry the set of types
-- present at the owner name.
--
-- An 'NsecTypes' may legitimately be empty -- this is the
-- expected encoding for an NSEC3 empty-non-terminal.  With NSEC,
-- the type bitmap is expected to include at least the 'NSEC' type
-- itself; that invariant is not enforced by the type.
--
-- Construction and enumeration go through 'IsList':
--
-- * @'fromList' tys :: 'NsecTypes'@ builds the bitmap from a list
--   of 'RRTYPE' values; duplicates are merged and the wire-form
--   ordering is canonical regardless of input order.  Under
--   @OverloadedLists@ the same input shape is just @[A, AAAA, MX]@.
-- * @'toList' bm :: ['RRTYPE']@ enumerates the contained types in
--   ascending wire-form order.
-- * @('<>')@ unions two bitmaps; 'mempty' is the empty bitmap.
--
-- For membership without enumerating the whole set, use
-- 'hasRRtype', which goes directly to the relevant window, block
-- and bit offset.
newtype NsecTypes = NsecTypes (IM.IntMap ShortByteString) deriving Eq

-- | The 'Ord' instance matches wire-form canonical order.
instance Ord NsecTypes where
    a `compare` b = asDnsTextMap a `compare` asDnsTextMap b
      where
        asDnsTextMap :: NsecTypes -> IM.IntMap DnsText
        asDnsTextMap = coerce

-- | Construction is via 'fromList' (from any list of 'RRTYPE's,
-- order and duplicates immaterial), and enumeration is via
-- 'toList' (yielding types in canonical wire-form order).
instance IsList NsecTypes where
    type Item NsecTypes = RRTYPE

    -- | Return the contained types in ascending wire-form order.
    toList   = nsecTypesToList

    -- | Build the bitmap from a list of types, deduplicating and
    -- ordering as needed.  An empty input produces the empty
    -- bitmap.
    fromList = nsecTypesFromList

instance Show NsecTypes where
    showsPrec p (toList -> tys) = showsP p $
        showString "fromList @NsecTypes "
        . shows' tys

-- | Presentation form: contained types in canonical wire-form
-- order, space-separated, with no leading separator.  The empty
-- bitmap renders as the empty string.  When the bitmap follows
-- another field in an RR's presentation form, compose with
-- 'presentSp' or 'presentLn' to prefix the appropriate separator.
instance Presentable NsecTypes where
    present ts k = case toList ts of
        t : rest -> present t $ foldr presentSp k rest
        []       -> k

-- | The @('<>')@ operator unions the two bitmaps; duplicate
-- types are merged.
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
    -- underlying storage is finally repackaged as a 'SB.ShortByteString'.
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
