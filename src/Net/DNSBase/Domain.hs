{-|
Module      : Net.DNSBase.Domain
Description : Domain/mailbox name data-type
Copyright   : (c) Viktor Dukhovni, 2020-2026
              (c) Peter Duchovni, 2020
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The 'Domain' data type represents the /wire form/ of DNS domain
names or mailbox names.  The internal representation is not
exposed, but is basically a 'ShortByteString' containing a
sequence of length-prefixed A-labels, including a terminal empty
label.  The labels must not be longer than 63 octets, and the
total length of the /wire form/ must not exceed 255 bytes.

The distinction between domain names and mailbox names exists only
at the level of /presentation form/, and they are otherwise the
same.  The standard /presentation form/ of a 'Domain' uses @\'.\'@
as a label separator, escaping any (rare) literal @\'.\'@
characters that happen to be part of the label content, and a
terminal dot is appended to the last label.  As a matter of
convenience, this module introduces an ad hoc /mailbox
presentation form/ of a multi-label 'Domain', which uses @\'\@\'@
as the separator between the first and second labels, and any
literal @\'.\'@ characters in the first label are not escaped.  In
the mailbox presentation form, no terminal @\'.\'@ is appended to
the address.

As 'ShortByteString' values, labels are composed of arbitrary
'Word8' elements.  The only constraint is that each label is at
most 63 bytes.

This module implements Template Haskell /splices/ for literal
domain names in application source files.  Literal strings are
validated and converted to /wire form/ at compile-time.  The
IDN-aware splice (RFC 5890+, Punycode encoding of U-labels) is the
canonical 'dnLit'; the byte-level splice that accepts arbitrary
8-bit labels is available as 'dnLit8':

> let d = $$(dnLit mkDomain "m\x00fc\&nchen.example.com") :: Domain  -- IDN-aware
> let d = $$(dnLit8 "haskell.example.com") :: Domain   -- byte-level
> let m = $$(mbLit8 "some.user@example.com") :: Domain

'dnLit' takes the presentation-form parser as its first argument:
the @mkDomain@ used above comes from the companion @idna2008@
package, which is the usual choice when IDN labels are expected.
For names known to be 8-bit clean (typically just ASCII), the
'dnLit8' and 'mbLit8' splices skip IDN processing entirely.

The runtime equivalents are 'makeDomain8' and 'makeMbox8' (and
the matching 'makeDomain8Str' / 'makeMbox8Str' for 'String'
input).  They accept the RFC 1035 master-file syntax described
below and return either a 'Domain' or a 'Domain8Err' describing
why the input was rejected.

Escape handling matches RFC 1035 master-file syntax:

  * @\\C@ for any byte @C@ appends @C@ as a single byte (the byte
    after the backslash is taken literally, with one exception: a
    trailing backslash is rejected with 'D8BadEscape').
  * @\\DDD@ for three ASCII decimal digits with @DDD <= 255@
    appends the byte with that decimal value.

Validation:

  * Each label is 1..63 bytes (empty non-final labels are rejected
    as 'D8EmptyLabel'; a sole @\'.\'@ or empty input both denote
    the root domain).
  * The wire form (all labels plus the terminator) is at most 255
    bytes; an overflow is reported as 'D8WireTooLong'.
-}
{-# LANGUAGE TemplateHaskell #-}

module Net.DNSBase.Domain
    ( -- ** Domain data type
      Domain(RootDomain)
    , DnsTriple(..)
    , Host
    , fromHost
    , toHost
    , Mbox
    , fromMbox
    , toMbox
    -- ** Domain and mailbox name literals
    , dnLit
    , mbLit
    , dnLit8
    , mbLit8
    -- ** Conversions
    -- *** Validating import from wire form
    , wireToDomain
    -- *** From presentation form with pluggable parsers
    , decodePresentationDomain
    , decodePresentationMbox
    -- *** Decoders for 8-bit presentation forms
    , Domain8Err(..)
    , makeDomain8
    , makeDomain8Str
    , makeMbox8
    , makeMbox8Str
    -- *** Canonicalisation to lower case
    , canonicalise
    -- *** Working with labels
    , appendDomain
    , consDomain
    , unconsDomain
    , labelCount
    , fromLabels
    , toLabels
    , revLabels
    , commonSuffix
    -- ** Binary serialization functions
    , mbWireForm
    , shortBytes
    , wireBytes
    -- ** Predicates
    , isLDHName
    , isLDHLabel
    -- ** Sorting and comparison
    , compareWireHost
    , equalWireHost
    , canonicalNameOrder
    , sortDomains
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Unsafe as BU
import qualified Data.Char as Ch
import qualified Language.Haskell.TH.Syntax as TH
import Control.Monad.ST (ST, runST)
import Data.Primitive.ByteArray
    ( MutableByteArray
    , copyMutableByteArray
    , newByteArray
    , unsafeFreezeByteArray
    , writeByteArray
    )

import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.Util

----------------------------------------------------------------------
-- Error type
----------------------------------------------------------------------

-- | Failure modes for the byte-level 8-bit presentation-form parser.
-- Intentionally coarse and position-free.  Callers that need richer
-- diagnostics should use the @idna2008@ parser.
data Domain8Err
    = D8LabelTooLong  -- ^ A label exceeds 63 bytes.
    | D8WireTooLong   -- ^ The wire form exceeds 255 bytes.
    | D8BadEscape     -- ^ A backslash escape is malformed: a trailing
                      --   @\\@, a truncated @\\DDD@, a non-digit in
                      --   @\\DDD@, or @\\DDD@ with value greater
                      --   than 255.
    | D8EmptyLabel    -- ^ An empty interior label (consecutive dots,
                      --   a leading dot followed by more input, or an
                      --   empty mailbox localpart with a non-empty
                      --   remainder after the unescaped @\@@).
    | D8Non8Bit       -- ^ ('String' input only) Source contained a
                      --   'Char' with codepoint above @0xFF@; the
                      --   8-bit path cannot encode it.
    | D8Non7Bit       -- ^ When parsing a mailbox presentation form, the
                      --   first label contained a non-ASCII byte.
    deriving (Eq, Show)

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

-- | Construct a 'Domain' object directly from a /presentation form/
-- 'ByteString'.
--
-- The bytes are not treated as UTF-8 content, and IDNA processing does not
-- apply.  Backslash-escape encoding aside, each 8-bit byte in the input is
-- copied verbatim into the wire-form domain.  For Unicode IDN domain support,
-- see the parsers in the @idna2008@ package.
--
-- ==== __Example__
-- >>> import qualified Data.ByteString.Char8 as BC
-- >>> dn = makeDomain8 $ BC.pack "www.corp.acme.example"
-- >>> dn
-- Right "www.corp.acme.example."
-- >>> toLabels <$> dn
-- Right ["www","corp","acme","example"]
--
makeDomain8 :: ByteString -> Either Domain8Err Domain
makeDomain8 = fmap Domain_ . parseDomain8Wire

-- | Construct a 'Domain' object directly from a /presentation
-- form/ 'ByteString' representing a mailbox.  As a convenience to
-- users, the separator between the first and remaining labels is
-- optionally the first unescaped @\'\@\'@ character, in which
-- case prior @\'.\'@ characters in the first label do not need to
-- be escaped.
--
-- The first label must not contain any non-ASCII bytes (above 127),
-- or an error ('Left') is returned.
--
-- The 'toMbox' function can be used to coerce the resulting
-- 'Domain' to an 'Mbox' object whose presentation form uses an
-- @\'\@\'@ between the first and remaining labels and does not
-- escape dots in the first label.
--
-- ==== __Example__
-- >>> import qualified Data.ByteString.Char8 as BC
-- >>> dn = makeMbox8 $ BC.pack "john.smith@acme.example"
-- >>> dn
-- Right "john\\.smith.acme.example."
-- >>> toLabels <$> dn
-- Right ["john.smith","acme","example"]
-- >>> toMbox <$> dn
-- Right "john.smith@acme.example"
--
makeMbox8 :: ByteString -> Either Domain8Err Domain
makeMbox8 = fmap Domain_ . parseMbox8Wire

-- | Same as 'makeDomain8', but the input is a 'String', and
-- an error ('Left') is also returned if any of the input
-- string's characters are outside the 8-bit range.
--
-- Note that UTF-8 encoding of names in the Latin-1 alphabet might
-- still produce surprising results.  For parsing IDN domain names,
-- see the @idna2008@ package.
--
-- ==== __Example__
-- >>> dn = makeDomain8Str "www.corp.acme.example"
-- >>> dn
-- Right "www.corp.acme.example."
-- >>> toLabels <$> dn
-- Right ["www","corp","acme","example"]
--
makeDomain8Str :: String -> Either Domain8Err Domain
makeDomain8Str = safePack >=> fmap Domain_ . parseDomain8Wire

-- | Same as 'makeMbox8', but the input is a 'String, and
-- an error ('Left why') is also returned if any of the input
-- string's characters are outside the 8-bit range.
--
-- The first label must not contain any non-ASCII bytes (above 127),
-- or an error ('Left') is returned.
--
-- Note that UTF-8 encoding of domain names in the Latin-1 alphabet
-- might still produce surprising results.  For parsing IDN domain
-- names, see the @idna2008@ package.
--
-- ==== __Example__
-- >>> dn = makeMbox8Str "john.smith@acme.example"
-- >>> dn
-- Right "john\\.smith.acme.example."
-- >>> toLabels <$> dn
-- Right ["john.smith","acme","example"]
-- >>> toMbox <$> dn
-- Right "john.smith@acme.example"
--
makeMbox8Str :: String -> Either Domain8Err Domain
makeMbox8Str = safePack >=> fmap Domain_ . parseMbox8Wire

----------------------------------------------------------------------
-- Wire-bytes parsers (internal byte-input variants)
----------------------------------------------------------------------

-- | Shared backbone: parse a 'ByteString' in /presentation form/ and
-- return the wire-form bytes (or a 'Domain8Err').
parseDomain8Wire :: ByteString -> Either Domain8Err ShortByteString
parseDomain8Wire !bs = runST do
    outBuf <- newByteArray outBufSize
    let !inEnd = B.length bs
    res <- domainDriver bs inEnd outBuf 0 0 1
    finalise outBuf res

-- | Mailbox-form analogue of 'parseDomain8Wire'.
parseMbox8Wire :: ByteString -> Either Domain8Err ShortByteString
parseMbox8Wire !bs =
    let !inEnd = B.length bs
    in case findAt8 bs 0 inEnd of
         Nothing    -> parseDomain8Wire bs
         Just sepAt -> runST do
            outBuf <- newByteArray outBufSize
            res <- mboxDriver bs inEnd outBuf sepAt
            finalise outBuf res

----------------------------------------------------------------------
-- Template-Haskell splices for compile-time literals
----------------------------------------------------------------------

-- | Template-Haskell splice for literal 'Domain' names that are
-- validated and converted from /presentation form/ to /wire form/
-- at compile-time.  Example:
--
-- > domain :: Domain
-- > domain = $$(dnLit8 "example.org")
--
-- This is the byte-level path: it accepts any 8-bit master-file
-- text but performs no IDN processing.  For IDN-aware literals (RFC
-- 5890+, Punycode A-label encoding) use 'dnLit' with a parser from
-- the companion @idna2008@ package.
dnLit8 :: forall m. (TH.Quote m, MonadFail m) => String -> TH.Code m Domain
dnLit8 s = TH.joinCode case makeDomain8Str s of
    Left why -> fail $ "Invalid literal domain " ++ show s ++ ": " ++ show why
    Right dn -> pure (TH.liftTyped dn)

-- | Template-Haskell splice for literal mailbox names.  Example:
--
-- > mbox :: Domain
-- > mbox = $$(mbLit8 "hostmaster@example.org")
--
-- Byte-level all the way through: the localpart and the domain
-- portion are both parsed by 'makeMbox8Str', which treats the
-- input as opaque 8-bit master-file text.  For EAI/UTF-8 localpart
-- semantics use 'mbLit' with an @idna2008@-style 'Text' parser.
mbLit8 :: forall m. (TH.Quote m, MonadFail m) => String -> TH.Code m Domain
mbLit8 s = TH.joinCode case makeMbox8Str s of
    Left why -> fail $ "Invalid mailbox literal " ++ show s ++ ": " ++ show why
    Right dn -> pure (TH.liftTyped dn)

----------------------------------------------------------------------
-- Domain driver
----------------------------------------------------------------------

-- | Walk a slice of @bs@ as a presentation-form domain, writing the
-- wire form into @outBuf@ starting at length-byte position
-- @startLStart@ (so the first label's length byte goes to
-- @outBuf[startLStart]@ and its first content byte to
-- @outBuf[startLStart + 1]@).
--
-- On success returns @Right outLen@ where the terminator goes at
-- @outBuf[outLen]@ (and @finalLen = outLen + 1@); on any error
-- returns @Left e@ for the appropriate 'Domain8Err'.
--
-- The driver tracks two boundary cases via @startLStart@: a sole
-- @\'.\'@ representing the root domain, and an empty post-localpart
-- domain part in the mailbox case (e.g. @\"a\@.\"@).
domainDriver
    :: forall s
    .  ByteString
    -> Int                              -- ^ inEnd
    -> MutableByteArray s
    -> Int                              -- ^ startLStart
    -> Int                              -- ^ iPos
    -> Int                              -- ^ initial oPos == startLStart + 1
    -> ST s (Either Domain8Err Int)
domainDriver !bs !inEnd !outBuf !startLStart = go startLStart
  where
    go :: Int -> Int -> Int -> ST s (Either Domain8Err Int)
    go !lStart !iPos !oPos
      | iPos >= inEnd = endOfInput lStart oPos
      | otherwise =
          let !b = BU.unsafeIndex bs iPos
          in if | b == 0x5C -> handleEsc lStart iPos oPos
                | b == 0x2E -> handleDot lStart iPos oPos
                | otherwise -> appendByte b lStart (iPos + 1) oPos

    appendByte :: Word8 -> Int -> Int -> Int -> ST s (Either Domain8Err Int)
    appendByte !b !lStart !iPos !oPos
      | oPos - lStart > maxLabelLen = pure (Left D8LabelTooLong)
      | oPos >= maxWireLen          = pure (Left D8WireTooLong)
      | otherwise = do
          writeByteArray outBuf oPos b
          go lStart iPos (oPos + 1)

    handleEsc :: Int -> Int -> Int -> ST s (Either Domain8Err Int)
    handleEsc !lStart !iPos !oPos
      | iPos + 1 >= inEnd = pure (Left D8BadEscape)
      | otherwise =
          let !b1 = BU.unsafeIndex bs (iPos + 1)
          in case asciiDigit b1 of
               Nothing -> appendByte b1 lStart (iPos + 2) oPos
               Just !v1
                 | iPos + 4 > inEnd -> pure (Left D8BadEscape)
                 | otherwise ->
                     let !b2 = BU.unsafeIndex bs (iPos + 2)
                         !b3 = BU.unsafeIndex bs (iPos + 3)
                     in case (asciiDigit b2, asciiDigit b3) of
                          (Just v2, Just v3)
                            | n <= 0xFF ->
                                appendByte (fromIntegral n) lStart
                                           (iPos + 4) oPos
                            | otherwise -> pure (Left D8BadEscape)
                            where
                              !n =   100 * fromIntegral v1
                                  +   10 * fromIntegral v2
                                  +        fromIntegral v3 :: Int
                          _ -> pure (Left D8BadEscape)

    handleDot :: Int -> Int -> Int -> ST s (Either Domain8Err Int)
    handleDot !lStart !iPos !oPos
      | oPos == lStart + 1 =
          -- Empty label.  Acceptable only as the root domain indicator
          -- at the very start of this driver call (no label has been
          -- emitted by us yet) and only when the dot is the last
          -- input byte.  Trailing dots after a real label hit the
          -- non-empty branch on the dot itself, then the
          -- end-of-input branch on the byte after.
          if lStart == startLStart && iPos + 1 == inEnd
            then go lStart (iPos + 1) oPos
            else pure (Left D8EmptyLabel)
      | otherwise = do
          let !labelLen = oPos - lStart - 1
          writeByteArray outBuf lStart (fromIntegral labelLen :: Word8)
          let !lStart' = oPos
              !oPos'   = lStart' + 1
          go lStart' (iPos + 1) oPos'

    endOfInput :: Int -> Int -> ST s (Either Domain8Err Int)
    endOfInput !lStart !oPos
      | oPos == lStart + 1 =
          -- Either no labels at all (lStart == startLStart) or a
          -- trailing dot just consumed (lStart > startLStart).  In
          -- both cases the terminator goes at outBuf[lStart].
          pure (Right lStart)
      | otherwise = do
          let !labelLen = oPos - lStart - 1
          writeByteArray outBuf lStart (fromIntegral labelLen :: Word8)
          pure (Right oPos)

----------------------------------------------------------------------
-- Localpart driver
----------------------------------------------------------------------

-- | Walk a slice of @bs@ in @[lpStart..lpEnd)@ as a mailbox
-- localpart, writing the localpart wire bytes into
-- @outBuf[1..]@.  Returns the number of bytes written (i.e. the
-- localpart length) on success.
--
-- Localpart parsing differs from domain parsing: there is exactly
-- one label (no @\'.\'@ separators), and the byte @\'.\'@ is
-- therefore literal.  Backslash escapes work the same way (@\\C@
-- and @\\DDD@).  Non-ASCII bytes (> 127) are rejected as invalid.
--
localpartDriver
    :: forall s.  ByteString
    -> Int -- ^ lpEnd
    -> MutableByteArray s
    -> ST s (Either Domain8Err Int)
localpartDriver !bs !lpEnd !outBuf = go 0 1
  where
    go :: Int -> Int -> ST s (Either Domain8Err Int)
    go !iPos !oPos
      | iPos >= lpEnd = pure (Right (oPos - 1))
      | otherwise =
          let !b = BU.unsafeIndex bs iPos
          in if | b == 0x5C -> handleEsc iPos oPos
                | otherwise -> appendByte b (iPos + 1) oPos

    appendByte :: Word8 -> Int -> Int -> ST s (Either Domain8Err Int)
    appendByte !b !iPos !oPos
      | b > 0x7F = pure (Left D8Non7Bit)
      | oPos > maxLabelLen = pure (Left D8LabelTooLong)
      | otherwise = do
          writeByteArray outBuf oPos b
          go iPos (oPos + 1)

    handleEsc :: Int -> Int -> ST s (Either Domain8Err Int)
    handleEsc !iPos !oPos
      | iPos + 1 >= lpEnd = pure (Left D8BadEscape)
      | b1 <- BU.unsafeIndex bs (iPos + 1)
      , v1 <- b1 - 0x30
      = if | v1 > 9 -> appendByte b1 (iPos + 2) oPos
           | iPos + 4 > lpEnd -> pure (Left D8BadEscape)
           | v2 <- BU.unsafeIndex bs (iPos + 2) - 0x30
           , v2 <= 9
           , v3 <- BU.unsafeIndex bs (iPos + 3) - 0x30
           , v3 <= 9
           , !n <- (v1 * 100 + v2 * 10 + v3)
           -> if | n <= 0xFF -> appendByte (fromIntegral n) (iPos + 4) oPos
                 | otherwise -> pure (Left D8BadEscape)
           | otherwise -> pure (Left D8BadEscape)

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
    -> ST s (Either Domain8Err Int)
mboxDriver !bs !inEnd !outBuf !sepAt = do
    res <- localpartDriver bs sepAt outBuf
    case res of
      Left e -> pure (Left e)
      Right lpLen
        | lpLen == 0 ->
            -- Empty localpart.  Accepted only as a sole "@" denoting
            -- the root domain (matches the historical behaviour of
            -- the Builder-based parser); rejected when followed by
            -- anything else (the empty first label has no business
            -- next to additional content).
            if sepAt + 1 >= inEnd
              then pure (Right 0)
              else pure (Left D8EmptyLabel)
        | lpLen <= maxLabelLen -> do
            writeByteArray @Word8 outBuf 0 (fromIntegral lpLen)
            let !lpEnd = fromIntegral $ lpLen + 1
            if sepAt + 1 >= inEnd
              then pure (Right lpEnd)
              else domainDriver bs inEnd outBuf
                                lpEnd (sepAt + 1) (lpEnd + 1)
        | otherwise -> pure (Left D8LabelTooLong)

-- | Single-pass scan for the first unescaped @\'\@\'@.  Returns the
-- byte offset of that @\'\@\'@, or 'Nothing' if none is present.
--
-- Backslash escapes are skipped in the same shape as the localpart
-- parser uses on input: @\\<digit>@ is the start of a 4-byte
-- @\\DDD@ form; @\\<other>@ is the 2-byte @\\C@ form.  A
-- structurally invalid escape (truncated) leaves the scan in
-- "no @ found" state, and the actual parse failure is reported by
-- 'parseDomain8Wire' (which the mailbox parser falls back to in the
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
-- length-check, and freeze into the wire-form 'ShortByteString'.
finalise
    :: forall s
    .  MutableByteArray s
    -> Either Domain8Err Int
    -> ST s (Either Domain8Err ShortByteString)
finalise !_ (Left e) = pure (Left e)
finalise !outBuf (Right outLen) =
    let !finalLen = outLen + 1
    in if finalLen > maxWireLen
         then pure (Left D8WireTooLong)
         else do
           writeByteArray outBuf outLen (0 :: Word8)
           resBA <- newByteArray finalLen
           copyMutableByteArray resBA 0 outBuf 0 finalLen
           frozen <- unsafeFreezeByteArray resBA
           pure (Right (baToShortByteString frozen))

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

-- | Pack a 'String' into a 'ByteString', failing with 'D8Non8Bit' if
-- any character has codepoint above @0xFF@.
safePack :: String -> Either Domain8Err ByteString
safePack s
    | all ((<= 0xFF) . Ch.ord) s = Right (C8.pack s)
    | otherwise                  = Left D8Non8Bit
