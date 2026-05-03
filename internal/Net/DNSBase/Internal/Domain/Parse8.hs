-- |
-- Module      : Net.DNSBase.Internal.Domain.Parse8
-- Description : Byte-level (8-bit) presentation-form parser for Domain
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-style
--
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
--
-- Byte-level presentation parser for 'Domain' and mailbox-form 'Domain'.
-- Walks a 'ByteString' byte-by-byte and writes the wire form directly
-- into a freshly allocated buffer, with no intermediate 'Builder' or
-- monadic-state machinery.
--
-- The error space is intentionally coarse: every parse failure returns
-- 'Nothing'.  Callers that need structured diagnostics should use the
-- IDNA-aware "Net.DNSBase.Internal.IDNA.Parse" parser instead.
--
-- Escape handling matches RFC 1035 master-file syntax:
--
--   * @\\C@ for any byte @C@ appends @C@ as a single byte (the byte
--     after the backslash is taken literally, with one exception: a
--     trailing backslash is rejected).
--   * @\\DDD@ for three ASCII decimal digits with @DDD <= 255@ appends
--     the byte with that decimal value.
--
-- Validation:
--
--   * Each label is 1..63 bytes (empty non-final labels are rejected;
--     a sole @\'.\'@ or empty input both denote the root domain).
--   * The wire form (all labels plus the terminator) is at most 255
--     bytes.
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE TemplateHaskell #-}

module Net.DNSBase.Internal.Domain.Parse8
    ( parseDomain8
    , parseMbox8
    , strToDomain8
    , dnLit8
    , mbLit8
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as SBS
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Char as Ch
import qualified Language.Haskell.TH.Lib as TH
import qualified Language.Haskell.TH.Syntax as TH
import Control.Monad ((>=>))
import Control.Monad.ST (ST, runST)
import Data.ByteString (ByteString)
import Data.Primitive.ByteArray
    ( MutableByteArray
    , copyMutableByteArray
    , newByteArray
    , unsafeFreezeByteArray
    , writeByteArray
    )
import Data.Word (Word8)

import Net.DNSBase.Internal.Domain (Domain(..), wireBytes)
import Net.DNSBase.Internal.Util (baToShortByteString)

----------------------------------------------------------------------
-- Buffer sizes
----------------------------------------------------------------------

-- | Maximum wire form length, RFC 1035 section 3.1.
maxWireLen :: Int
maxWireLen = 255

-- | Maximum wire octets in a single label.
maxLabelLen :: Int
maxLabelLen = 63

-- | Output buffer capacity (one extra byte over 'maxWireLen' so that
-- a transient @oPos == maxWireLen@ during dot-handling does not need
-- a guard before the next iteration's read picks up the overflow).
outBufSize :: Int
outBufSize = maxWireLen + 1

----------------------------------------------------------------------
-- Public entry points
----------------------------------------------------------------------

-- | Attempt to parse a 'ByteString' in /presentation form/ as a
-- domain name.  Invalid (including overly-long) input returns
-- 'Nothing'.
parseDomain8 :: ByteString -> Maybe Domain
parseDomain8 !bs = runST do
    outBuf <- newByteArray outBufSize
    let !inEnd = B.length bs
    res <- domainDriver bs inEnd outBuf 0 0 1
    finalise outBuf res

-- | Attempt to parse a 'ByteString' in /presentation form/ as a
-- mailbox name.  Invalid (including overly-long) input returns
-- 'Nothing'.
--
-- The first label is conceptually the local part of an email address,
-- and may contain literal periods that are not label separators.  When
-- the input contains an unescaped @\'\@\'@, it is the localpart-domain
-- separator; otherwise the input is parsed as a regular domain via
-- 'parseDomain8'.
parseMbox8 :: ByteString -> Maybe Domain
parseMbox8 !bs =
    let !inEnd = B.length bs
    in case findAt8 bs 0 inEnd of
         Nothing    -> parseDomain8 bs
         Just sepAt -> runST do
            outBuf <- newByteArray outBufSize
            res <- mboxDriver bs inEnd outBuf sepAt
            finalise outBuf res

-- | Attempt to parse a 'String' in /presentation form/ as a domain
-- name.  All characters must be in the range @[0..255]@ ('Char's
-- are interpreted as raw bytes).  Invalid input returns 'Nothing'.
strToDomain8 :: String -> Maybe Domain
strToDomain8 = safePack >=> parseDomain8

-- | Attempt to parse a 'String' in /presentation form/ as a mailbox
-- name.  All characters must be in the range @[0..255]@.  Invalid
-- input returns 'Nothing'.
strToMbox8 :: String -> Maybe Domain
strToMbox8 = safePack >=> parseMbox8

----------------------------------------------------------------------
-- Template-Haskell splices for compile-time literals
----------------------------------------------------------------------

-- | Template-Haskell splice for literal 'Domain' names that are
-- validated and converted from /presentation form/ to /wire form/
-- at compile-time.  Example:
--
-- > domain :: Domain
-- > domain = $$(dnLit8 "example.org")
dnLit8 :: forall m. (MonadFail m, TH.Quote m) => String -> TH.Code m Domain
dnLit8 s = TH.liftCode $ fmap TH.TExp $ case strToDomain8 s of
    Just dn -> TH.appE (TH.conE 'Domain)
                       (TH.appE (TH.varE 'SBS.toShort)
                                (TH.lift (wireBytes dn)))
    Nothing -> fail $ "Invalid domain-name literal: " ++ show s

-- | Template-Haskell splice for literal mailbox names that are
-- validated and converted from /presentation form/ to /wire form/
-- at compile-time.  Example:
--
-- > mbox :: Domain
-- > mbox = $$(mbLit8 "hostmaster@example.org")
mbLit8 :: (TH.Quote m, MonadFail m) => String -> TH.Code m Domain
mbLit8 s = TH.liftCode $ fmap TH.TExp $ case strToMbox8 s of
    Just dn -> TH.appE (TH.conE 'Domain)
                       (TH.appE (TH.varE 'SBS.toShort)
                                (TH.lift (wireBytes dn)))
    Nothing -> fail $ "Invalid mailbox-name literal: " ++ show s

----------------------------------------------------------------------
-- Domain driver
----------------------------------------------------------------------

-- | Walk a slice of @bs@ as a presentation-form domain, writing the
-- wire form into @outBuf@ starting at length-byte position
-- @startLStart@ (so the first label's length byte goes to
-- @outBuf[startLStart]@ and its first content byte to
-- @outBuf[startLStart + 1]@).
--
-- On success, returns @Just outLen@ where the terminator goes at
-- @outBuf[outLen]@ (and @finalLen = outLen + 1@); on any error
-- returns 'Nothing'.
--
-- The driver tracks two boundary cases via @startLStart@: a sole
-- @\'.\'@ representing the root, and an empty post-localpart
-- domain part in the mailbox case (e.g. @\"a\@.\"@).
domainDriver
    :: forall s
    .  ByteString
    -> Int                              -- ^ inEnd
    -> MutableByteArray s
    -> Int                              -- ^ startLStart
    -> Int                              -- ^ iPos
    -> Int                              -- ^ initial oPos == startLStart + 1
    -> ST s (Maybe Int)
domainDriver !bs !inEnd !outBuf !startLStart = go startLStart
  where
    go :: Int -> Int -> Int -> ST s (Maybe Int)
    go !lStart !iPos !oPos
      | iPos >= inEnd = endOfInput lStart oPos
      | otherwise =
          let !b = BU.unsafeIndex bs iPos
          in if | b == 0x5C -> handleEsc lStart iPos oPos
                | b == 0x2E -> handleDot lStart iPos oPos
                | otherwise -> appendByte b lStart (iPos + 1) oPos

    appendByte :: Word8 -> Int -> Int -> Int -> ST s (Maybe Int)
    appendByte !b !lStart !iPos !oPos
      | oPos - lStart > maxLabelLen = pure Nothing
      | oPos >= maxWireLen          = pure Nothing
      | otherwise = do
          writeByteArray outBuf oPos b
          go lStart iPos (oPos + 1)

    handleEsc :: Int -> Int -> Int -> ST s (Maybe Int)
    handleEsc !lStart !iPos !oPos
      | iPos + 1 >= inEnd = pure Nothing
      | otherwise =
          let !b1 = BU.unsafeIndex bs (iPos + 1)
          in case asciiDigit b1 of
               Nothing -> appendByte b1 lStart (iPos + 2) oPos
               Just !v1
                 | iPos + 4 > inEnd -> pure Nothing
                 | otherwise ->
                     let !b2 = BU.unsafeIndex bs (iPos + 2)
                         !b3 = BU.unsafeIndex bs (iPos + 3)
                     in case (asciiDigit b2, asciiDigit b3) of
                          (Just v2, Just v3)
                            | n <= 0xFF ->
                                appendByte (fromIntegral n) lStart
                                           (iPos + 4) oPos
                            | otherwise -> pure Nothing
                            where
                              !n =   100 * fromIntegral v1
                                  +   10 * fromIntegral v2
                                  +        fromIntegral v3 :: Int
                          _ -> pure Nothing

    handleDot :: Int -> Int -> Int -> ST s (Maybe Int)
    handleDot !lStart !iPos !oPos
      | oPos == lStart + 1 =
          -- Empty label.  Acceptable only as the root indicator at
          -- the very start of this driver call (no label has been
          -- emitted by us yet) and only when the dot is the last
          -- input byte.  Trailing dots after a real label hit the
          -- non-empty branch on the dot itself, then the
          -- end-of-input branch on the byte after.
          if lStart == startLStart && iPos + 1 == inEnd
            then go lStart (iPos + 1) oPos
            else pure Nothing
      | otherwise = do
          let !labelLen = oPos - lStart - 1
          writeByteArray outBuf lStart (fromIntegral labelLen :: Word8)
          let !lStart' = oPos
              !oPos'   = lStart' + 1
          go lStart' (iPos + 1) oPos'

    endOfInput :: Int -> Int -> ST s (Maybe Int)
    endOfInput !lStart !oPos
      | oPos == lStart + 1 =
          -- Either no labels at all (lStart == startLStart) or a
          -- trailing dot just consumed (lStart > startLStart).  In
          -- both cases the terminator goes at outBuf[lStart].
          pure (Just lStart)
      | otherwise = do
          let !labelLen = oPos - lStart - 1
          writeByteArray outBuf lStart (fromIntegral labelLen :: Word8)
          pure (Just oPos)

----------------------------------------------------------------------
-- Localpart driver
----------------------------------------------------------------------

-- | Walk a slice of @bs@ in @[lpStart..lpEnd)@ as a mailbox
-- localpart, writing the localpart wire bytes into
-- @outBuf[1..]@.  Returns the number of bytes written (i.e. the
-- localpart length) on success.
--
-- Localpart parsing differs from domain parsing in two ways: there
-- is exactly one label (no @\'.\'@ separators), and the byte
-- @\'.\'@ is therefore literal.  Backslash escapes work the same
-- way (@\\C@ and @\\DDD@).
localpartDriver
    :: forall s
    .  ByteString
    -> Int                              -- ^ lpEnd
    -> MutableByteArray s
    -> ST s (Maybe Int)
localpartDriver !bs !lpEnd !outBuf = go 0 1
  where
    go :: Int -> Int -> ST s (Maybe Int)
    go !iPos !oPos
      | iPos >= lpEnd = pure (Just (oPos - 1))
      | otherwise =
          let !b = BU.unsafeIndex bs iPos
          in if | b == 0x5C -> handleEsc iPos oPos
                | otherwise -> appendByte b (iPos + 1) oPos

    appendByte :: Word8 -> Int -> Int -> ST s (Maybe Int)
    appendByte !b !iPos !oPos
      | oPos > maxLabelLen = pure Nothing
      | otherwise = do
          writeByteArray outBuf oPos b
          go iPos (oPos + 1)

    handleEsc :: Int -> Int -> ST s (Maybe Int)
    handleEsc !iPos !oPos
      | iPos + 1 >= lpEnd = pure Nothing
      | otherwise =
          let !b1 = BU.unsafeIndex bs (iPos + 1)
          in case asciiDigit b1 of
               Nothing -> appendByte b1 (iPos + 2) oPos
               Just !v1
                 | iPos + 4 > lpEnd -> pure Nothing
                 | otherwise ->
                     let !b2 = BU.unsafeIndex bs (iPos + 2)
                         !b3 = BU.unsafeIndex bs (iPos + 3)
                     in case (asciiDigit b2, asciiDigit b3) of
                          (Just v2, Just v3)
                            | n <= 0xFF ->
                                appendByte (fromIntegral n) (iPos + 4) oPos
                            | otherwise -> pure Nothing
                            where
                              !n =   100 * fromIntegral v1
                                  +   10 * fromIntegral v2
                                  +        fromIntegral v3 :: Int
                          _ -> pure Nothing

----------------------------------------------------------------------
-- Mailbox driver
----------------------------------------------------------------------

-- | Parse a mailbox in presentation form.  @sepAt@ is the byte
-- offset of the first unescaped @\'\@\'@ (already located by
-- 'findAt8').  Walks the localpart bytes @[0..sepAt)@, then
-- dispatches @[sepAt+1..inEnd)@ to 'domainDriver' for the
-- domain-side labels.
mboxDriver
    :: forall s
    .  ByteString
    -> Int                              -- ^ inEnd
    -> MutableByteArray s
    -> Int                              -- ^ sepAt
    -> ST s (Maybe Int)
mboxDriver !bs !inEnd !outBuf !sepAt = do
    res <- localpartDriver bs sepAt outBuf
    case res of
      Nothing     -> pure Nothing
      Just lpLen
        | lpLen == 0 ->
            -- Empty localpart.  Accepted only as a sole "@" denoting
            -- the root domain (matches the historical behaviour of
            -- the Builder-based parser); rejected when followed by
            -- anything else.
            if sepAt + 1 >= inEnd
              then pure (Just 0)
              else pure Nothing
        | lpLen > maxLabelLen -> pure Nothing
        | otherwise -> do
            writeByteArray outBuf 0 (fromIntegral lpLen :: Word8)
            let !lpEnd = lpLen + 1
            if sepAt + 1 >= inEnd
              then pure (Just lpEnd)
              else domainDriver bs inEnd outBuf
                                lpEnd (sepAt + 1) (lpEnd + 1)

-- | Single-pass scan for the first unescaped @\'\@\'@.  Returns the
-- byte offset of that @\'\@\'@, or 'Nothing' if none is present.
--
-- Backslash escapes are skipped in the same shape as the localpart
-- parser uses on input: @\\<digit>@ is the start of a 4-byte
-- @\\DDD@ form; @\\<other>@ is the 2-byte @\\C@ form.  A
-- structurally invalid escape (truncated) leaves the scan in
-- "no @ found" state, and the actual parse failure is reported by
-- 'parseDomain8' (which the mailbox parser falls back to in the
-- no-@ case).
findAt8 :: ByteString -> Int -> Int -> Maybe Int
findAt8 !bs !p0 !inEnd = go p0
  where
    go !p
      | p >= inEnd = Nothing
      | otherwise =
          let !b = BU.unsafeIndex bs p
          in if | b == 0x40 -> Just p
                | b == 0x5C -> skipEsc p
                | otherwise -> go (p + 1)

    skipEsc !p
      | p + 1 >= inEnd = Nothing
      | otherwise =
          let !b1 = BU.unsafeIndex bs (p + 1)
          in case asciiDigit b1 of
               Just _  -> go (p + 4)
               Nothing -> go (p + 2)

----------------------------------------------------------------------
-- Buffer finalisation
----------------------------------------------------------------------

-- | Common tail: append a terminator to @outBuf@ at @outLen@,
-- length-check, and freeze into a 'Domain'.
finalise
    :: forall s
    .  MutableByteArray s
    -> Maybe Int
    -> ST s (Maybe Domain)
finalise !_ Nothing = pure Nothing
finalise !outBuf (Just outLen) =
    let !finalLen = outLen + 1
    in if finalLen > maxWireLen
         then pure Nothing
         else do
           writeByteArray outBuf outLen (0 :: Word8)
           resBA <- newByteArray finalLen
           copyMutableByteArray resBA 0 outBuf 0 finalLen
           frozen <- unsafeFreezeByteArray resBA
           pure (Just (Domain (baToShortByteString frozen)))

----------------------------------------------------------------------
-- Tiny utilities
----------------------------------------------------------------------

-- | If @w@ is an ASCII decimal digit, return its numeric value
-- (0..9); otherwise 'Nothing'.
asciiDigit :: Word8 -> Maybe Word8
asciiDigit !w
    | d <= 9    = Just d
    | otherwise = Nothing
  where
    !d = w - 0x30
{-# INLINE asciiDigit #-}

-- | Pack a 'String' into a 'ByteString', failing if any character
-- is outside @[0..255]@.
safePack :: String -> Maybe ByteString
safePack s
    | all ((<= 0xFF) . Ch.ord) s = Just (C8.pack s)
    | otherwise                  = Nothing
