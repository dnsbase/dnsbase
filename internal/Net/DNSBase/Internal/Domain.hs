-- |
-- Module      : Net.DNSBase.Internal.Domain
-- Description : TBD
-- Copyright   : (c) Viktor Dukhovni, 2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
{-# LANGUAGE
    DeriveLift
  , DerivingStrategies
  , RecordWildCards
  , TemplateHaskell
  #-}

module Net.DNSBase.Internal.Domain
    ( -- ** Domain name data type
      Domain(.., RootDomain)
    , DnsTriple(..)
    , Host
    , fromHost
    , toHost
    , Mbox
    , fromMbox
    , toMbox
    -- *** Canonicalisation to lower case
    , canonicalise
    -- *** Working with labels
    , appendDomain
    , consDomain
    , unconsDomain
    , fromLabels
    , labelCount
    , toLabels
    , revLabels
    , commonSuffix
    -- ** Validating import from wire form
    , wireToDomain
    -- ** Decode presentation form to Domain
    , decodePresentationDomain
    , decodePresentationMbox
    -- ** Compile-time literals
    , dnLit
    , mbLit
    -- ** Binary serialization functions
    , wireBytes
    , mbWireForm
    -- ** Predicates
    , isLDHLabel
    , isLDHName
    -- ** Sorting and comparison
    , compareWireHost
    , equalWireHost
    , canonicalNameOrder
    , sortDomains
    ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Builder.Extra as B
import qualified Data.ByteString.Short as SB
import qualified Data.ByteString.Unsafe as B
import qualified Data.List as L
import qualified Data.Primitive.ByteArray as A
import qualified Data.Text as T
import qualified Data.Text.Array as TA
import qualified Data.Text.Internal as TI
import qualified Data.Text.Unsafe as T
import qualified Language.Haskell.TH.Syntax as TH
import Control.Monad.ST (ST, runST)
import Data.Bifunctor (first)
import Data.Foldable (foldlM)

import Net.DNSBase.Encode.Internal.Metric
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.RRCLASS
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.Text
import Net.DNSBase.Internal.Util

---------------------------------------- Domain newtype

-- | This type holds the /wire form/ of fully-qualified DNS domain
-- names encoded as A-labels.
--
-- The encoding of valid domain names to /presentation form/ (the
-- 'Presentable' instance) performs any required escaping of
-- special characters to ensure lossless round-trip encoding and
-- decoding of valid DNS names, and compatibility with the
-- standard zone file format.  Valid names are not limited to the
-- letter-digit-hyphen (LDH) syntax of hostnames, all 8-bit
-- characters are allowed in DNS names, subject to the 63-byte
-- limit on /wire form/ label length and 255-byte limit on the
-- /wire form/ domain name (including the terminal empty label).
--
-- Equality and comparison are based on the wire-form and are
-- case-sensitive.  The 'Host' newtype implements case-insensitive
-- equality and comparison over the same wire-form bytes.  The
-- 'toHost' and 'fromHost' functions implement coercions between
-- the two types.
--
newtype Domain = Domain_
    {
    -- | The /wire form/ of a domain name, including the zero-valued
    -- length byte of the terminal empty label.
    shortBytes :: ShortByteString
    } deriving stock TH.Lift
      deriving newtype (Eq, Ord)


-- | Coercible to/from a domain, but its presentation form is canonical (lower
-- case) and has no terminating @.@, unless this is the root domain.
--
-- Equality and order are on the wire form, but are case-insensitive.
newtype Host = Host ShortByteString

-- | Case-insensitive equality on the wire form.
instance Eq Host where
    a == b = fromHost a `equalWireHost` fromHost b

-- | Case-insensitive order on the wire form.
instance Ord Host where
    a `compare` b = fromHost a `compareWireHost` fromHost b

-- | Coerce a 'Domain' to a 'Host'.
toHost :: Domain -> Host;   toHost = coerce
-- | Coerce a 'Host' to a 'Domain'.
fromHost :: Host -> Domain; fromHost = coerce


-- | Coercible to\/from a domain, but its presentation form uses the @\@@ sign
-- as the separator after the first label, and does not escape literal @.@
-- characters within the first label. The second and subsequent labels are
-- canonicalised to lower-case.  No terminating @.@ is appended unless this
-- is the root domain.
--
-- Equality and order are on the wire form, but are case-insensitive.
newtype Mbox = Mbox ShortByteString deriving (Eq, Ord) via Host

-- | Coerce a 'Domain' to an 'Mbox'.  This changes the presentation form
-- to one in which the first label is separated from the rest by an @\'\@\'@
-- character, and any dots in the first label remain unescaped. No period
-- is appended after the last label.  The same form can be parsed by:
--
-- * 'Net.DNSBase.Domain.mbLit8'
-- * 'Net.DNSBase.Domain.makeMbox8'
-- * 'Net.DNSBase.Domain.makeMbox8Str'
-- * 'mbLit'
-- * 'decodePresentationMbox'
--
-- provided the first label (localpart) uses only 7-bit ASCII characters.
-- Mailboxes with non-ASCII localparts (EAI addresses) must be valid UTF-8
-- and can only be parsed by 'decodePresentationMbox' or 'mbLit', but
-- the presentation form of 'Mbox' does escapes all non-ASCII bytes in
-- @\\DDD@ decimal form, and would be rejected by all the above parsers.
-- A UTF-8 presentation form that respects EAI addresses is not yet
-- available, and would probably want a new @EAIMbox@ data type.
--
toMbox :: Domain -> Mbox;   toMbox = coerce
-- | Coerce an 'Mbox' to a 'Domain'.
fromMbox :: Mbox -> Domain; fromMbox = coerce


-- | An /RRSet/ is uniquely idenfified by a name, type, class triple.
data DnsTriple = DnsTriple {
    dnsTripleName  :: Domain
  , dnsTripleType  :: RRTYPE
  , dnsTripleClass :: RRCLASS
  } deriving (Eq, Show)

instance Presentable DnsTriple where
    present DnsTriple {..} =
        present dnsTripleName
        . presentSp dnsTripleClass
        . presentSp dnsTripleType


-- | The internal representation of Domains is not exposed, so neither the the
-- wire form nor any labels except the last can be empty.  The total length
-- cannot exceed 255 and no label can be longer than 63 bytes.
impossible :: a
impossible = error "Impossible wire format domain"

rootDomain :: Domain
rootDomain = coerce $ SB.singleton 0

-- | The root 'Domain' (presentation form @.@).
pattern RootDomain :: Domain
pattern RootDomain <- Domain_ (SB.length -> 1) where
    RootDomain = rootDomain

-- | Return the wire form of a 'Domain' name as a 'ByteString'
wireBytes :: Domain -> ByteString
wireBytes = SB.fromShort . shortBytes

-- | Case-insensitive equality of domain names.
equalWireHost :: Domain -> Domain -> Bool
equalWireHost (Domain_ sa) (Domain_ sb)
    | lena /= lenb                                 = False
    | A.compareByteArrays arra 0 arrb 0 lena == EQ = True
    | otherwise                                    = go 0
  where
    lena = SB.length sa
    lenb = SB.length sb
    arra = sbsToByteArray sa
    arrb = sbsToByteArray sb

    go !off
        | off + 1 == lena = True
        | tolower wa /= tolower wb = False
        | otherwise = go $ off + 1
      where
        wa = A.indexByteArray arra off
        wb = A.indexByteArray arrb off

-- | Canonical name order:
-- <https://datatracker.ietf.org/doc/html/rfc4034#section-6.1>.  For sorting
-- lists of more than a few elements, it may be best to perform a /decorate/,
-- sort, /undecorate/ via 'sortDomains'.
--
canonicalNameOrder :: Domain -> Domain -> Ordering
canonicalNameOrder a b
    | a `equalWireHost` b = EQ
    | otherwise = compare (revLabels $ canonicalise a)
                          (revLabels $ canonicalise b)

-- | Case-insensitive comparison of the wire forms of domains.
compareWireHost :: Domain -> Domain -> Ordering
compareWireHost (Domain_ sa) (Domain_ sb) = go 0
  where
    lena = SB.length sa
    lenb = SB.length sb
    arra = sbsToByteArray sa
    arrb = sbsToByteArray sb

    go !off
        | off + 1 == lena = compare lena lenb
        | off + 1 == lenb = compare lena lenb
        | cmp /= EQ       = cmp
        | otherwise       = go $ off + 1
      where
        wa = A.indexByteArray arra off
        wb = A.indexByteArray arrb off
        cmp = compare (tolower wa) (tolower wb)

-- | Perform a /decorate/, sort, /undecorate/ sort to return a list of domains
-- in canonical order.
sortDomains :: [Domain] -> [Domain]
sortDomains = L.sortOn (revLabels . canonicalise)

-- | Conversion to /presentation form/ via a bytestring 'Builder'.
instance Presentable Domain where
    present = presentDomain
    -- | Executes the 'Domain' builder with sensibly short buffers.
    presentLazy d k = B.toLazyByteStringWith domainStrat k $ present d mempty

-- | Conversion to /presentation form/ via a bytestring 'Builder'.
instance Presentable Host where
    present = presentHost . coerce
    -- | Executes the 'Host' builder with sensibly short buffers.
    presentLazy h k = B.toLazyByteStringWith domainStrat k $ present h mempty

-- | Conversion to /presentation form/ via a bytestring 'Builder'.
instance Presentable Mbox where
    present = presentMbox . coerce
    -- | Executes the 'Mbox' builder with sensibly short buffers.
    presentLazy m k = B.toLazyByteStringWith domainStrat k $ present m mempty

-- | Shows the presentation form string, adding double quotes and additional
-- string escapes as needed.  To get the /raw/ string, use 'presentString'.
instance Show Domain where
    showsPrec p d = showsPrec p $ presentString d mempty

-- | Shows the presentation form string, adding double quotes and additional
-- string escapes as needed.  To get the /raw/ string, use 'presentString'.
instance Show Host where
    showsPrec p h = showsPrec p $ presentString h mempty

-- | Shows the presentation form string, adding double quotes and additional
-- string escapes as needed.  To get the /raw/ string, use 'presentString'.
instance Show Mbox where
    showsPrec p m = showsPrec p $ presentString m mempty

---------------------------------------- Conversions


-- | Given two 'Domain's attempt to construct a new new domain consisting
-- of the labels of the first, followed by the labels of the second.  Fails
-- (returns 'Nothing') if the result would be too long.
--
appendDomain :: Domain -> Domain -> Maybe Domain
appendDomain p@(subtract 1 . coerce SB.length -> plen)
             s@(coerce SB.length -> slen)
    | plen == 0 = Just s
    | slen == 1 = Just p
    | len <- plen + slen
    , len < 256 = Just $! Domain_ $ combine len
    | otherwise = Nothing
  where
    combine len = baToShortByteString $ A.runByteArray do
        mba <- A.newByteArray len
        A.copyByteArray mba 0 (sbsToByteArray $ shortBytes p) 0 plen
        A.copyByteArray mba plen (sbsToByteArray $ shortBytes s) 0 slen
        pure mba


-- | Canonicalise a 'Domain' to lower-case form.
canonicalise :: Domain -> Domain
canonicalise domain@(shortBytes -> bytes)
    | SB.any isupper bytes = Domain_ $ SB.map tolower bytes
    | otherwise = domain


-- | Attempt to prepend the given label to the given domain, provided the label
-- length is 63 bytes or less, and the resulting domain is not too long.
--
consDomain :: ShortByteString -> Domain -> Maybe Domain
consDomain label@(SB.length -> llen)  suffix@(coerce SB.length -> slen) = do
    let len = llen + 1 + slen
    guard $ llen > 0 && llen <= 63 && len < 256
    pure $! Domain_ $ combine len
  where
    combine len = baToShortByteString $ A.runByteArray do
        mba <- A.newByteArray len
        A.writeByteArray mba 0 (i2w llen)
        A.copyByteArray mba 1 (sbsToByteArray label) 0 llen
        A.copyByteArray mba (llen+1) (sbsToByteArray $ shortBytes suffix) 0 slen
        pure mba


-- | Given a 'Domain', return a tuple containing its first unescaped label as a
-- 'ShortByteString' and the remainder of the 'Domain' after removing the first
-- label.  Returns 'Nothing' for the root domain.
--
unconsDomain :: Domain -> Maybe (ShortByteString, Domain)
unconsDomain (Domain_ sbs)
    | len > 1   = Just (label, Domain_ suffix)
    | otherwise = Nothing
  where
    len     = SB.length sbs
    ba      = sbsToByteArray sbs
    llen    = w2i $ A.indexByteArray ba 0
    slen    = len - llen - 1
    !label  = baToShortByteString $ A.cloneByteArray ba 1 llen
    !suffix = baToShortByteString $ A.cloneByteArray ba (llen + 1) slen


-- | Given a constituent list of raw unescaped labels, construct the
-- corresponding /wire form/ domain name. No label may be empty or longer than
-- 63 bytes, and the number of labels + the sum of label lengths must not
-- exceed 254.  The return value is 'Nothing' if the length constraints are
-- violated.
--
-- prop> fromLabels (toLabels dn) == Just dn
fromLabels :: [ShortByteString] -> Maybe Domain
fromLabels ls = do
    len <- foldlM space 1 ls
    pure $! Domain_ $ combine len
  where
    space :: Int -> ShortByteString -> Maybe Int
    space acc (SB.length -> len)
        | len > 0 && len < 64
        , new <- acc + len + 1
        , new < 256 = Just new
        | otherwise = Nothing

    combine len = baToShortByteString $ A.runByteArray do
        mba <- A.newByteArray len
        go mba 0 ls

    go mba off (l : rest) = do
        let !llen = SB.length l
        A.writeByteArray mba off $ i2w llen
        A.copyByteArray mba (off+1) (sbsToByteArray l) 0 llen
        go mba (off + llen + 1) rest
    go mba off _ = mba <$ A.writeByteArray @Word8 mba off 0


-- | Validating import of a wire-form 'ShortByteString' as a
-- 'Domain'.  Returns 'Just' iff the bytes are a well-formed DNS
-- domain on the wire:
--
--   * total length in @1..255@,
--   * every label length byte in @1..63@ except the trailing
--     zero-byte root label,
--   * label boundaries align exactly with the buffer end -- i.e.
--     the terminating empty label's NUL length-byte is the last
--     byte, and there is no truncation or trailing garbage.
--
-- Suitable for receiving bytes the caller cannot prove
-- well-formed (e.g. labels handed back by a foreign library or
-- another package).  Wire-form bytes that come straight from the
-- decoder in "Net.DNSBase.Decode.Domain" are already validated and
-- do not need to round-trip through this check.
wireToDomain :: ShortByteString -> Maybe Domain
wireToDomain sbs
    | total >= 1, total <= 255, walk 0 = Just (Domain_ sbs)
    | otherwise                        = Nothing
  where
    !arr   = sbsToByteArray sbs
    !total = SB.length sbs

    walk :: Int -> Bool
    walk !off
        | off >= total = False    -- ran off end without hitting root NUL
        | otherwise =
            let !lb = w2i (A.indexByteArray arr off :: Word8)
            in if lb == 0
                 then off + 1 == total              -- root NUL is the last byte
                 else lb <= 63 && off + 1 + lb < total
                                && walk (off + 1 + lb)


-- | Template-Haskell typed splice for a compile-time 'Domain'
-- literal.  The caller supplies a parser of type
-- @'Text' -> 'Either' e 'ShortByteString'@; @dnLit@ packs the
-- source 'String' literal as 'Text', runs the parser at compile
-- time, additionally checks the bytes via 'wireToDomain', and
-- embeds the resulting 'Domain' as a constant.  An invalid literal
-- (parser failure /or/ wire-shape failure) becomes a compile-time
-- error.
--
-- The @dnsbase@ library deliberately does not bundle a domain
-- parser; users compose a parser of their choice and pass it in.
-- The natural source of validating parsers is the @idna2008@
-- package, whose parsers already operate on 'Text'.
-- Template-Haskell staging forbids referring to a same-module
-- top-level binding from inside the splice, so the parser must
-- either be defined in an /imported/ module or bound by a @let@
-- /inside/ the splice; for a single-call site the latter is the
-- more compact form:
--
-- > import qualified Text.IDNA2008 as I
-- >
-- > example :: Domain
-- > example = $$(let parser = fmap I.wireBytesShort . I.mkDomain
-- >               in dnLit parser "www.example.org")
--
-- @mkDomain@ runs strict IDNA2008 with default label forms and
-- no mappings, returning just the validated @idna2008@ library\'s
-- 'Domain' object.  The @I.wireBytesShort@ function extracts the
-- wire form bytes needed by 'dnLit'.
--
-- For looser policies (mappings, emoji domain tolerance, etc.) use
-- @parseDomainOpt@ with an explicit @LabelFormSet@ and @IDNAOpts@,
-- and discard the @LabelInfo@ half of its result.
--
-- Hoisting the parser into a separate module avoids retyping the
-- composition at every literal:
--
-- > -- in MyDomainParsers.hs
-- > strictParser :: Text -> Either I.IdnaError ShortByteString
-- > strictParser = fmap I.wireBytesShort . I.mkDomain
-- >
-- > -- in any module that imports MyDomainParsers
-- > example :: Domain
-- > example = $$(dnLit strictParser "www.example.org")
--
-- The source literal is converted to 'Text' before the parser is
-- invoked; literals whose UTF-8 byte length exceeds 1024 are
-- rejected as invalid without consulting the parser.  The emitted
-- splice is a constant 'Domain' value (the wire-form
-- 'ShortByteString' is materialised once from its compile-time
-- @Addr#@ literal on first evaluation); the splice itself runs no
-- runtime IDNA code, and the caller's binary carries no
-- @idna2008@ dependency unless the user imports it themselves.
--
dnLit :: forall e m. (Show e, MonadFail m, TH.Quote m)
      => (Text -> Either e ShortByteString) -- ^ Parser
      -> String -- ^ Input literal (source code shape)
      -> TH.Code m Domain
dnLit parse s = TH.joinCode case packBounded mboxPresentationMaxBytes s of
    Nothing -> fail $ "Invalid literal domain " ++ show s
                   ++ ": presentation form longer than "
                   ++ show mboxPresentationMaxBytes ++ " bytes"
    Just t  -> case parse t of
        Left why -> fail $ "Invalid literal domain " ++ show s
                        ++ ": " ++ show why
        Right bs -> case wireToDomain bs of
            Just dn -> pure (TH.liftTyped dn)
            Nothing -> fail $ "Invalid domain: " ++ show s

----------------------------------------------------------------------
-- Decode a presentation-form domain
----------------------------------------------------------------------

-- | Decode a domain in presentation form.  The caller supplies the
-- parser; this entry point validates the parser's output as a
-- wire-form 'ShortByteString' that 'wireToDomain' accepts.
--
-- When the parser returns an error @e@, the return value is
-- @Left (Just e)@.  If a buggy parser produces an invalid wire
-- form, the return value is @Left Nothing@.
decodePresentationDomain
    :: forall e
    .  (Text -> Either e ShortByteString) -- ^ Parser
    -> Text                               -- ^ Input to be parsed
    -> Either (Maybe e) Domain
decodePresentationDomain parser t = case parser t of
    Right bs -> maybe (Left Nothing) Right $ wireToDomain bs
    Left why -> Left $ Just why

----------------------------------------------------------------------
-- Decode a presentation-form mbox
----------------------------------------------------------------------

-- | Parse a presentation-form mailbox into a 'Domain'.
--
-- The input is split at the first unescaped @\'\@\'@ if any;
-- otherwise at the first unescaped @\'.\'@; otherwise the entire
-- input is the localpart and the resulting 'Domain' has a single
-- non-root label.  A separator present but followed by empty
-- domain text (e.g. @\"postmaster\@\"@ or @\"postmaster.\"@) is
-- treated the same way as if the separator were absent: the
-- localpart is one label, the domain part is the root domain.
--
-- Following EAI semantics (RFC 6532), the localpart's wire bytes
-- are either pure 7-bit ASCII or a well-formed UTF-8 sequence.
-- The localpart decoder:
--
--   * Copies unescaped 'Text' bytes verbatim into the wire form.
--     A 'Text' is already valid UTF-8, so the bytes for one
--     codepoint are 1, 2, 3 or 4 bytes long depending on the
--     codepoint; no decoding or validation is needed.
--   * @\\DDD@ (three ASCII decimal digits, @0..127@) emits the
--     single ASCII byte with that value.  Values @>= 128@ are
--     rejected.
--   * @\\X@ (any other single character) emits @X@ as a single
--     ASCII byte; @X@'s codepoint must be @< 0x80@.
--
-- The rules above apply only to the /localpart/ -- the first
-- label of the mailbox name.  The post-separator 'Text' (if any)
-- is handed verbatim to the caller-supplied domain parser, which
-- decodes any remaining labels.
--
-- The parser's output is validated to be a wire-form
-- 'ShortByteString' that 'wireToDomain' accepts.  If length
-- limits permit, the decoded localpart is prepended to form the
-- combined 'Domain'.
--
-- When the parser returns an error @e@, the return value is
-- @Left (Just e)@.  If a buggy parser produces an invalid wire
-- form, the return value is @Left Nothing@.
decodePresentationMbox
    :: forall e
    .  (Text -> Either e ShortByteString) -- ^ Parser
    -> Text                               -- ^ Input to be parsed
    -> Either (Maybe e) Domain
decodePresentationMbox parseDom t = do
    (lpBytes, rest) <- maybe (Left Nothing) pure $ runST (decodeLocalpart t)
    if SB.length lpBytes > 63
        then Left Nothing
        else do
            !domWire <- if T.null rest
                            then Right rootWire
                            else first Just (parseDom rest)
            let !combined = lpBytes <> domWire
            maybe (Left Nothing) Right $ wireToDomain combined
  where
    !rootWire = SB.singleton 0

----------------------------------------------------------------------
-- Localpart byte walker
----------------------------------------------------------------------

-- | Snapshot of the buffer position when the optimistic @\'\@\'@-mode
-- walker passes an unescaped @\'.\'@.  If the walker reaches
-- end-of-input without seeing an unescaped @\'\@\'@ the snapshot
-- becomes the chosen separator and the localpart is truncated to
-- the bytes that came before the dot.
data DotSnap
    = NoDot
    | DotAt {-# UNPACK #-} !Int  -- ^ buffer position at the dot
            {-# UNPACK #-} !Int  -- ^ source-array offset after the dot

-- | Decode the localpart of a presentation-form mailbox.  Returns
-- the length-prefixed wire-form bytes for the localpart's label
-- (one length byte plus the content bytes) together with the
-- unconsumed remainder of the input (the slice of 'Text' after
-- the separator, or empty if no separator was found).
--
-- 'Nothing' indicates a malformed localpart (bad escape, length
-- overflow, raw @>= 128@ byte from a literal escape).
--
-- The walker chooses the separator by cheap presence-scanning the
-- first 256 bytes of the input for an @\'\@\'@ byte (0x40, which
-- can't appear inside a UTF-8 continuation sequence).  Finding
-- one switches the walker to @\'\@\'@-optimistic mode with a
-- @\'.\'@-snapshot fallback; otherwise the walker uses
-- @\'.\'@-only mode.  The 256-byte window is enough: the largest
-- valid localpart presentation form (63 wire bytes, each encoded
-- as @\\DDD@) fits in 252 bytes plus one for the @\'\@\'@.
decodeLocalpart :: forall s. Text -> ST s (Maybe (ShortByteString, Text))
decodeLocalpart (TI.Text src srcOff srcLen) = do
    buf <- A.newByteArray 64
    A.writeByteArray buf 0 (0 :: Word8)
    if firstAtIn srcOff (min 256 srcLen) src
        then loopAt buf 1 NoDot srcOff
        else loopDot buf 1 srcOff
  where
    !srcEnd = srcOff + srcLen

    -- @\'\@\'@-optimistic walker.  Records the position of the first
    -- unescaped @\'.\'@ as a fallback in case every @\'\@\'@ is escaped.
    loopAt :: A.MutableByteArray s -> Int -> DotSnap -> Int
           -> ST s (Maybe (ShortByteString, Text))
    loopAt buf !bufPos !snap !i
      | i >= srcEnd = case snap of
            NoDot              -> finalise buf bufPos srcEnd
            DotAt dp dskip     -> finalise buf dp dskip
      | otherwise = case TA.unsafeIndex src i of
            0x40  {- '@' -}  -> finalise buf bufPos (i + 1)
            0x5C  {- '\\' -} -> case decodeEscape src (i + 1) srcEnd of
                Nothing      -> pure Nothing
                Just (b, i') -> putByte buf bufPos b
                                  (loopAt buf (bufPos + 1) snap i')
            0x2E  {- '.' -}  ->
                let !snap' = case snap of
                        NoDot -> DotAt bufPos (i + 1)
                        _     -> snap
                in putByte buf bufPos 0x2E
                     (loopAt buf (bufPos + 1) snap' (i + 1))
            c | c < 0x80     -> putByte buf bufPos c
                                  (loopAt buf (bufPos + 1) snap (i + 1))
              | otherwise    -> copyUtf8 buf bufPos i c $ \bufPos' i' ->
                                  loopAt buf bufPos' snap i'

    -- @\'.\'@-only walker (no @\'\@\'@ in the first 256 bytes of input).
    loopDot :: A.MutableByteArray s -> Int -> Int
            -> ST s (Maybe (ShortByteString, Text))
    loopDot buf !bufPos !i
      | i >= srcEnd = finalise buf bufPos srcEnd
      | otherwise = case TA.unsafeIndex src i of
            0x2E  {- '.' -}  -> finalise buf bufPos (i + 1)
            0x5C  {- '\\' -} -> case decodeEscape src (i + 1) srcEnd of
                Nothing      -> pure Nothing
                Just (b, i') -> putByte buf bufPos b
                                  (loopDot buf (bufPos + 1) i')
            c | c < 0x80     -> putByte buf bufPos c
                                  (loopDot buf (bufPos + 1) (i + 1))
              | otherwise    -> copyUtf8 buf bufPos i c $ \bufPos' i' ->
                                  loopDot buf bufPos' i'

    -- Write a single byte at 'bufPos' and continue with @k@.
    -- Rejects writes past the 64-byte buffer (slots 0..63).
    putByte :: A.MutableByteArray s -> Int -> Word8
            -> ST s (Maybe a) -> ST s (Maybe a)
    putByte buf !bufPos !b k
      | bufPos > 63 = pure Nothing
      | otherwise   = do A.writeByteArray buf bufPos b
                         k

    -- Copy a UTF-8 multi-byte sequence (width determined by the
    -- lead byte) from 'src' at offset @i@ into 'buf' at @bufPos@.
    -- The 'Text' input is well-formed UTF-8, so no decoding or
    -- validation is needed: just byte-copy the continuation bytes.
    copyUtf8 :: A.MutableByteArray s -> Int -> Int -> Word8
             -> (Int -> Int -> ST s (Maybe a)) -> ST s (Maybe a)
    copyUtf8 buf !bufPos !i !lead k
      | bufPos + width > 64 = pure Nothing
      | otherwise = do
          A.writeByteArray @Word8 buf bufPos lead
          copyTrailing 1
          k (bufPos + width) (i + width)
      where
        !width
          | lead < 0xC0 = 1  -- never hit for well-formed Text
          | lead < 0xE0 = 2
          | lead < 0xF0 = 3
          | otherwise   = 4
        copyTrailing !j
          | j >= width = pure ()
          | otherwise  = do
              A.writeByteArray buf (bufPos + j)
                  (TA.unsafeIndex src (i + j))
              copyTrailing (j + 1)

    -- Stamp the length byte at slot 0, copy the used prefix into
    -- a 'ShortByteString', and slice the remaining input.
    finalise :: A.MutableByteArray s -> Int -> Int
             -> ST s (Maybe (ShortByteString, Text))
    finalise buf !bufPos !restOff = do
        let !contentLen = bufPos - 1
        A.writeByteArray buf 0 (fromIntegral contentLen :: Word8)
        let collect !i !acc
              | i < 0     = pure acc
              | otherwise = do
                  b <- A.readByteArray buf i
                  collect (i - 1) (b : acc)
        bytes <- collect (bufPos - 1) []
        let !sbs  = SB.pack (bytes :: [Word8])
            !rest = TI.Text src restOff (srcEnd - restOff)
        pure $ Just (sbs, rest)

-- | True if a @\'\@\'@ byte (0x40) appears anywhere in
-- @arr[off..off+lim-1]@.  Used as a cheap presence test before
-- choosing the localpart walker's separator policy.  An @\'\@\'@
-- is ASCII and so cannot appear inside a UTF-8 multi-byte
-- sequence, so a plain byte scan reliably finds every literal
-- occurrence in the input (escaped ones are also matched, but
-- the walker will reject them and fall back to the
-- @\'.\'@-snapshot).
firstAtIn :: Int -> Int -> TA.Array -> Bool
firstAtIn !off !lim arr = go off
  where
    !end = off + lim
    go !i
      | i >= end                        = False
      | TA.unsafeIndex arr i == 0x40    = True
      | otherwise                       = go (i + 1)

-- | Decode a @\\@-escape starting at @arr[off]@ (the byte
-- /after/ the backslash).  Returns the decoded byte and the
-- offset of the byte just past the escape.  Both @\\DDD@
-- (three ASCII decimal digits, @0..127@) and @\\X@ (any other
-- single ASCII byte) decode to a single ASCII byte; values
-- @>= 128@ are rejected.
decodeEscape :: TA.Array -> Int -> Int -> Maybe (Word8, Int)
decodeEscape arr !i !srcEnd
    | i >= srcEnd = Nothing
    | !w <- TA.unsafeIndex arr i
    , !d <- fromIntegral (w - 0x30)
    = if | w > 0x7f  -> Nothing
         | d > 9     -> Just (w, i + 1)
         | i + 3 > srcEnd -> Nothing
         | !e <- fromIntegral (TA.unsafeIndex arr (i + 1) - 0x30), e <= 9
         , !f <- fromIntegral (TA.unsafeIndex arr (i + 2) - 0x30), f <= 9
         , !n <- 100 * d + 10 * e + f :: Int
         , n < 0x80  -> Just (fromIntegral n, i + 3)
         | otherwise -> Nothing

-- | Pack a 'String' to 'Text', rejecting inputs whose UTF-8
-- byte length exceeds @maxBytes@.  Used by 'dnLit' and 'mbLit' to
-- short-circuit obviously-invalid literal inputs before invoking
-- the user parser.
--
-- The implementation uses 'T.unfoldrN' with a codepoint cap of
-- @maxBytes + 1@, which terminates even on infinite input
-- 'String's: a codepoint is at least one UTF-8 byte, so
-- consuming @maxBytes + 1@ codepoints is always sufficient to
-- decide whether the input fits within the @maxBytes@-byte cap.
packBounded :: Int -> String -> Maybe Text
packBounded !maxBytes s
    | T.lengthWord8 t > maxBytes = Nothing
    | otherwise                  = Just t
  where
    !t = T.unfoldrN (maxBytes + 1) L.uncons s

-- | Upper bound on the length of a valid mailbox or domain
-- presentation form, in UTF-8 bytes.  Anything longer is rejected
-- before the parser is invoked.  The worst case is a fully
-- @\\DDD@-escaped 254-octet name with full-width Unicode dots
-- between labels -- still well under 1024 bytes, so this is a
-- generous over-estimate that catches accidental overlong inputs
-- without putting a precise limit on legitimate ones.
mboxPresentationMaxBytes :: Int
mboxPresentationMaxBytes = 1024

-- | Template-Haskell typed splice for a compile-time mailbox
-- literal.  Packs the source 'String' literal as 'Text'
-- (rejecting inputs longer than 1024 bytes) and hands it to
-- 'decodePresentationMbox': the localpart is parsed locally with
-- DNS-style escapes, and the post-separator domain text is passed
-- to the caller-supplied parser.  An invalid literal (localpart
-- failure /or/ domain-parser failure /or/ combined-length
-- failure) becomes a compile-time error.
--
-- The parser argument has the same shape as 'dnLit'\'s:
-- @'Text' -> 'Either' e 'ShortByteString'@.  The user can pass
-- the same parser they pass to 'dnLit' (typically a composition
-- with @idna2008@), and the mailbox literal inherits the same IDN
-- policy for the domain portion of the name.  See 'dnLit' for the
-- standard idioms.
mbLit :: forall e m. (Show e, MonadFail m, TH.Quote m)
      => (Text -> Either e ShortByteString) -- ^ Parser
      -> String -- ^ Input literal (source code shape)
      -> TH.Code m Domain
mbLit parse s = TH.joinCode case packBounded mboxPresentationMaxBytes s of
    Nothing -> fail $ "Invalid mailbox literal " ++ show s
                   ++ ": presentation form longer than "
                   ++ show mboxPresentationMaxBytes ++ " bytes"
    Just t  -> case decodePresentationMbox parse t of
        Left e  -> fail $ "Invalid mailbox literal " ++ show s
                       ++ ": " ++ maybe mempty show e
        Right d -> pure (TH.liftTyped d)


-- | Given a 'Domain/, return its label count.  The root domain has zero labels.
--
-- >>> labelCount $$(dnLit8 "example.org")
-- 2
--
-- >>> toLabels $$(mbLit8 "first.last@example.org")
-- 3
--
labelCount :: Domain -> Word
labelCount (sbsToByteArray . shortBytes -> arr) = go 0 0
  where
    go :: Word -> Int -> Word
    go !acc !off
        | w <- A.indexByteArray arr off
        , w /= 0    = go (acc + 1) (off + w2i w + 1)
        | otherwise = acc

-- | Does the given 'Domain' name consist entirely of LDH labels?
isLDHName :: Domain -> Bool
isLDHName = go . SB.unpack . shortBytes
  where
    go :: [Word8] -> Bool
    go [] = impossible
    go (0:[]) = True
    go (w:ws)
        | Just rest <- goLabels 0 (w2i w) ws
          = go rest
        | otherwise = False

    goLabels :: Int -> Int -> [Word8] -> Maybe [Word8]
    goLabels !_ !_ [] = impossible
    goLabels !_ !0 !_ = impossible
    goLabels !_ 1  (!b:rest)
        | isLDByte b = Just rest
        | otherwise = Nothing
    goLabels 0 !len  (!b:bs)
        | isLDByte b  = goLabels 1 (len - 1) bs
        | otherwise = Nothing
    goLabels !off !len (!b:bs)
        | isLDHByte b = goLabels (off + 1) (len - 1) bs
        | otherwise = Nothing

-- | Is the given 'ShortByteString' a valid non-empty LDH label?
isLDHLabel :: ShortByteString -> Bool
isLDHLabel = go <$> SB.length <*> SB.unpack
  where
    go len bytes
        | len > 0 && len < 64 = goBytes 0 len bytes
        | otherwise = False

    goBytes :: Int -> Int -> [Word8] -> Bool
    goBytes !_ !_ [] = impossible
    goBytes !_ !0 _  = impossible
    goBytes !_ !1 (!b:_) = isLDByte b
    goBytes !0 !len (!b:bs)
        | isLDByte b = goBytes 1 (len - 1) bs
        | otherwise = False
    goBytes !off !len (!b:bs)
        | isLDHByte b = goBytes (off + 1) (len - 1) bs
        | otherwise = False

isLDByte :: Word8 -> Bool
isLDByte w
    | w - 0x30 < 10            = True
    | (w .&. 0xdf) - 0x41 < 26 = True
    | otherwise                = False

isLDHByte :: Word8 -> Bool
isLDHByte w
    | w - 0x30 < 10            = True
    | (w .&. 0xdf) - 0x41 < 26 = True
    | w == 0x2d                = True
    | otherwise                = False


-- | Given a 'Domain/, return its constituent list of raw unescaped labels,
-- most-significant (TLD) label last.
--
-- >>> toLabels $$(dnLit8 "example.org")
-- ["example","org"]
--
-- >>> toLabels $$(mbLit8 "first.last@example.org")
-- ["first.last","example","org"]
--
toLabels :: Domain -> [ShortByteString]
toLabels (Domain_ sbs) = go 0
  where
    ba  = sbsToByteArray sbs
    go !off
        | llen <- w2i $ A.indexByteArray ba off
        , llen /= 0
        , l <- baToShortByteString $ A.cloneByteArray ba (off+1) llen
          = l : go (off + llen + 1)
        | otherwise = []


-- | Given a Domain, return its constituent list of raw unescaped labels in
-- reverse order, with the TLD first.
--
-- >>> revLabels $$(dnLit8 "example.org")
-- ["org","example"]
--
-- >>> revLabels $$(mbLit8 "first.last@example.org")
-- ["org","example","first.last"]
--
revLabels :: Domain -> [ByteString]
revLabels = go [] . wireBytes
  where
    go acc !bs
        | B.length bs > 1
          = let !llen = w2i $ B.unsafeHead bs
                !rest = B.unsafeTail bs
                !lbs = B.unsafeTake llen rest
             in go (lbs : acc) (B.unsafeDrop llen rest)
        | otherwise
          = acc


-- | Return the longest common suffix of two input domains.
commonSuffix :: Domain -> Domain -> Domain
commonSuffix (Domain_ s1) (Domain_ s2) = go (min len1 len2) 0 0
  where
    len1 = SB.length s1
    len2 = SB.length s2
    ba1  = sbsToByteArray s1
    ba2  = sbsToByteArray s2

    -- When leading labels or suffix lengths are unequal, discard the label
    -- that leaves the shortest suffix, reducing the maximum match size to its
    -- length.  When they're equal, and leave equal length suffixes retain the
    -- match size and continue with both suffixes.  Once either suffix is just
    -- the root domain, we're done.  If both get there at the same time, 'sz'
    -- is the common suffix length.
    go sz off1 off2
        | i1 == 0 || i2 == 0
          = if | i1 /= i2 || sz == 1 -> RootDomain
               | otherwise           -> tailSlice
        | r1 >= sz
          = go sz t1 off2
        | r2 >= sz
          = go sz off1 t2
        | r2 < r1
          = go r2 t1 off2
        | r2 > r1
          = go r1 off1 t2
        | i1 /= i2 || EQ /= A.compareByteArrays ba1 off1 ba2 off2 i1
          = go r1 t1 t2
        | otherwise
          = go sz t1 t2
      where
        i1 = w2i $ A.indexByteArray ba1 off1
        t1 = off1 + i1 + 1
        r1 = len1 - t1
        i2 = w2i $ A.indexByteArray ba2 off2
        t2 = off2 + i2 + 1
        r2 = len2 - t2
        tailSlice = Domain_ $
            baToShortByteString $ A.cloneByteArray ba1 (len1 - sz) sz


-- | Encode a 'Domain' name without name compression
mbWireForm :: Domain -> SizedBuilder
mbWireForm d = mbShortByteString (shortBytes d)
{-# INLINE mbWireForm #-}

---------------------------------------- Wire -> Presentation

-- | Build the standard (dot-terminated) /presentation form/ of 'Domain'.
presentDomain :: Domain -> Builder -> Builder
presentDomain RootDomain = presentByte W_dot
presentDomain (shortBytes -> sb) = go 0
  where
    go :: Int -> Builder -> Builder
    go !pos@(fromIntegral . SB.index sb -> !llen)
        | llen == 0 = id
        | otherwise = presentDomainLabelSlice W_dot sb (pos + 1) llen
                    . presentByte W_dot
                    . go (pos + llen + 1)

-- | Build the canonical /presentation form/ of a 'Host' as a
-- lower-case name without a trailing dot.  The root domain is
-- nevertheless presented as a single @.@ byte.
--
presentHost :: Domain -> Builder -> Builder
presentHost RootDomain = presentByte W_dot
presentHost (shortBytes -> sb) = go 0
  where
    !end = SB.length sb - 1
    go :: Int -> Builder -> Builder
    go !pos@(fromIntegral . SB.index sb -> !llen)
        | !next <- pos + llen + 1
        , next /= end = presentHostLabelSlice W_dot sb (pos + 1) llen
                      . presentByte W_dot . go next
        | otherwise   = presentHostLabelSlice W_dot sb (pos + 1) llen

-- | Build the /mailbox form/ of a 'Domain', without a trailing
-- dot, and with @\'\@\'@ as the first label separator.
--
-- With single-label names we need to escape both 'W_dot' and
-- 'W_at', so the separator passed to 'canon' must be 'W_dot'
-- in that case, even if it would otherwise be 'W_at'.
--
presentMbox :: Domain -> Builder -> Builder
presentMbox RootDomain = presentByte W_dot
presentMbox (shortBytes -> sb) = go W_at 0
  where
    !end = SB.length sb - 1
    go :: Word8 -> Int -> Builder -> Builder
    go !sep !pos@(fromIntegral . SB.index sb -> !llen)
        | !next <- pos + llen + 1
        , next /= end = presentDomainLabelSlice sep sb (pos + 1) llen
                      . presentByte sep . go W_dot next
        | otherwise   = presentDomainLabelSlice W_dot sb (pos + 1) llen

-- | Walk a slice of a 'ShortByteString' applying 'domainLabelBP'.
presentDomainLabelSlice
    :: Word8 -> ShortByteString -> Int -> Int -> Builder -> Builder
{-# INLINE presentDomainLabelSlice #-}
presentDomainLabelSlice sep sb off len k =
    primMapShortByteStringSliceBounded (domainLabelBP sep) off len sb <> k

-- | Walk a slice of a 'ShortByteString' applying 'hostLabelBP'.
presentHostLabelSlice
    :: Word8 -> ShortByteString -> Int -> Int -> Builder -> Builder
{-# INLINE presentHostLabelSlice #-}
presentHostLabelSlice sep sb off len k =
    primMapShortByteStringSliceBounded (hostLabelBP sep) off len sb <> k

---------------------------------------- Util

-- | Most domain names are short, use small buffers, but no need to make them
-- too tight since we ultimately copy again into a short bytestring.
domainStrat :: B.AllocationStrategy
domainStrat = B.untrimmedStrategy 32 128

w2i :: Word8 -> Int
w2i = fromIntegral
{-# INLINE w2i #-}

i2w :: Int -> Word8
i2w = fromIntegral
{-# INLINE i2w #-}

-- | Upper case ASCII letter?
{-# INLINE isupper #-}
isupper :: Word8 -> Bool
isupper w = (w - 0x41 < 26)

-- | Map upper case ASCII to lower case.
{-# INLINE tolower #-}
tolower :: Word8 -> Word8
tolower w | isupper w = w + 32
tolower w = w
