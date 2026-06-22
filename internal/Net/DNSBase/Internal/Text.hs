-- |
-- Module      : Net.DNSBase.Internal.Text
-- Description : TBD
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
module Net.DNSBase.Internal.Text
    ( DnsText(..)
    , DnsUtf8Text(..)
    , dnsTextCmp
    , presentCharString
    , presentDomainLabel
    , presentHostLabel
    , presentCSVList
    , domainLabelBP
    , hostLabelBP
    ) where

import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Builder.Internal as B
import qualified Data.ByteString.Builder.Prim as P
import qualified Data.ByteString.Builder.Prim.Internal as P
import qualified Data.ByteString.Short as SB
import qualified Data.Text as T
import qualified Data.Text.Array as TA
import qualified Data.Text.Internal as T
import Data.ByteString.Builder.Prim ((>$<), (>*<))

import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util

newtype DnsText = DnsText SB.ShortByteString -- ^ Character string
    deriving (Eq, Show)

-- | Canonical wire-form comparison of DNS character strings.
instance Ord DnsText where
    (DnsText a) `compare` (DnsText b) = SB.length a `compare` SB.length b
                                     <>           a `compare`           b

instance Presentable DnsText where
    present = presentCharString . coerce

-- | Compare wire-form /character-strings/, by length first.
dnsTextCmp :: Coercible a ShortByteString => a -> a -> Ordering
dnsTextCmp x y = DnsText (coerce x) `compare` DnsText (coerce y)

-- | Present a dns /character-string/ with the given continuation.
-- The result is enclosed in double-quotes.
--
presentCharString :: SB.ShortByteString  -- ^ The bytes to encode.
                  -> Builder             -- ^ Continuation
                  -> B.Builder
{-# INLINE presentCharString #-}
presentCharString (SB.fromShort -> bytes) k =
    B.word8 W_dquote <> P.primMapByteStringBounded bp bytes <> B.word8 W_dquote <> k
  where
    isprint = \w -> w >= W_space && w < W_delete
    bp = P.condB isprint sp decEscBP
    sp = P.condB special bsEscBP charBP
    special = \ case
        W_dquote -> True
        W_bslash -> True
        _        -> False

-- | Present a 'Net.DNSBase.Domain.Domain' label with the given continuation.
--
presentDomainLabel :: Word8       -- ^ Label separator, typically 0x2e ('.').
                   -> ByteString  -- ^ The bytes to encode.
                   -> Builder     -- ^ Continuation
                   -> B.Builder
{-# INLINE presentDomainLabel #-}
presentDomainLabel sep bytes k =
    P.primMapByteStringBounded (domainLabelBP sep) bytes <> k

-- | 'BoundedPrim' driving 'presentDomainLabel'-style per-byte
-- presentation-form escaping with the given label separator
-- (typically 0x2e, @\'.\'@).  Exposed so that callers walking an
-- unpinned byte source (e.g.\ a 'ShortByteString' slice via
-- 'primMapShortByteStringSliceBounded') can apply the same escape
-- rules without going through a pinned 'ByteString'.
domainLabelBP :: Word8 -> P.BoundedPrim Word8
{-# INLINE domainLabelBP #-}
domainLabelBP sep = bp
  where
    isgraph = \w -> w > W_space && w < W_delete
    bp = P.condB isgraph sp decEscBP
    sp = P.condB special bsEscBP charBP
    special = \ case
        W_dquote -> True
        W_bslash -> True
        W_dollar -> True
        W_open   -> True
        W_close  -> True
        W_semi   -> True
        W_at     -> True
        w        -> w == sep

-- | Present a 'Net.DNSBase.Domain.Host' label folded to lower case, with the given continuation.
--
presentHostLabel :: Word8       -- ^ Label separator, typically 0x2e ('.').
                 -> ByteString  -- ^ The bytes to encode.
                 -> Builder     -- ^ Continuation
                 -> B.Builder
{-# INLINE presentHostLabel #-}
presentHostLabel sep bytes k =
    P.primMapByteStringBounded (hostLabelBP sep) bytes <> k

-- | 'BoundedPrim' driving 'presentHostLabel'-style per-byte
-- presentation-form escaping with lowercase folding of ASCII
-- uppercase letters.
hostLabelBP :: Word8 -> P.BoundedPrim Word8
{-# INLINE hostLabelBP #-}
hostLabelBP sep = bp
  where
    isgraph = \w -> w > W_space && w < W_delete
    bp = P.condB isgraph sp decEscBP
    sp = P.condB special bsEscBP (toLower >$< charBP)
    special = \ case
        W_dquote -> True
        W_bslash -> True
        W_dollar -> True
        W_open   -> True
        W_close  -> True
        W_semi   -> True
        W_at     -> True
        w        -> w == sep
    toLower w | w - W_A > 25 = w
              | otherwise     = w .|. 0x20

-- | Present a 'Net.DNSBase.Domain.Host' label folded to lower case, with the given continuation.
--
presentCSVList :: [SB.ShortByteString]  -- ^ The elements to encode.
               -> Builder               -- ^ Continuation
               -> B.Builder
{-# INLINE presentCSVList #-}
presentCSVList [] = presentByte W_dquote . presentByte W_dquote
presentCSVList (x : xs) =
    pelem W_dquote x
    . flip (foldr (pelem W_comma)) xs
    . presentByte W_dquote
  where
    pelem :: Word8 -> ShortByteString -> Builder -> Builder
    pelem sep = \sb k -> B.word8 sep <> P.primMapByteStringBounded bp (SB.fromShort sb) <> k
    isprint = \w -> w >= W_space && w < W_delete
    bp = P.condB isprint sp decEscBP'
    sp = P.condB special bsEscBP' charBP
    special = \ case
        W_dquote -> True
        W_bslash -> True
        W_comma  -> True
        _        -> False
    -- Two layers of escaping for backslashes and commas, require writing some
    -- backslashes twice:
    -- > "     -> \"
    -- > <DEL> -> \\127
    -- > ,     -> \\,
    -- > \     -> \\\\
    decEscBP' = (W_bslash,) >$< charBP >*< decEscBP
    bsEscBP'  = P.condB (== W_dquote) bsEscBP
              $ P.condB (== W_bslash) bsEsc''' bsEsc''
    bsEsc''   = (W_bslash,) . (W_bslash,)
            >$< charBP >*< charBP >*< charBP
    bsEsc'''  = (W_bslash,) . (W_bslash,) . (W_bslash,)
            >$< charBP >*< charBP >*< charBP >*< charBP

-----

-- | Supports UTF8 character strings, which are presented like all other
-- character strings, but must be valid UTF8 on the wire, and when unescaped
-- from presentation form.
newtype DnsUtf8Text = DnsUtf8Text T.Text
    deriving (Eq, Ord, Show)

instance Presentable DnsUtf8Text where
    present t = \ k ->
        B.word8 W_dquote
        <> encodeUtf8CharString (coerce t)
        <> B.word8 W_dquote
        <> k

-- | Support for escaping all non-special characters
-- Based on 'T.encodeUtf8BuilderEscaped'
encodeUtf8CharString :: T.Text -> B.Builder
encodeUtf8CharString = \txt -> B.builder (mkBuildstep txt)
  where
    printable = \w -> w >= W_space && w < W_delete
    bp = P.condB printable sp decEscBP
    sp = P.condB special bsEscBP charBP
    special = \ case
        W_dquote -> True
        W_bslash -> True
        _        -> False
    bound = P.sizeBound bp

    mkBuildstep :: T.Text -> B.BuildStep r -> B.BuildStep r
    mkBuildstep (T.Text arr off len) !k =
        outerLoop off
      where
        iend = off + len

        outerLoop !i0 !br@(B.BufferRange op0 ope)
          | i0 >= iend       = k br
          | outRemaining > 0 = goPartial (i0 + min outRemaining inpRemaining)
          | otherwise        = return $ B.bufferFull bound op0 (outerLoop i0)
          where
            outRemaining = (ope `minusPtr` op0) `quot` bound
            inpRemaining = iend - i0

            goPartial !iendTmp = go i0 op0
              where
                go !i !op
                  | i < iendTmp = do
                    let w = TA.unsafeIndex arr i
                    P.runB bp w op >>= go (i + 1)
                  | otherwise = outerLoop i (B.BufferRange op ope)
