{-# LANGUAGE
    DeriveLift
  , DerivingStrategies
  , RecordWildCards
  , TemplateHaskell
  #-}

module Net.DNSBase.Internal.Domain
    ( -- ** Domain name data type
      Domain(Domain, RootDomain)
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
    -- ** Mailbox-form parser
    , MboxErr(..)
    , parseMbox
    -- ** Compile-time literals
    , dnLit
    , mbLit
    -- ** Binary serialization functions
    , shortBytes
    , wireBytes
    , mbWireForm
    , buildDomain
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
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Builder.Extra as B
import qualified Data.ByteString.Short as SB
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Unsafe as B
import qualified Data.Char as Char
import qualified Data.List as L
import qualified Data.Primitive.ByteArray as A
import qualified Language.Haskell.TH.Syntax as TH
import Data.Bifunctor (first)
import Data.Foldable (foldlM)
import Data.Hashable (Hashable(..))

import Net.DNSBase.Encode.Internal.Metric
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.RRCLASS
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.Text
import Net.DNSBase.Internal.Util

---------------------------------------- Domain newtype

-- | This type holds the /wire form/ of fully-qualified DNS domain names
-- encoded as A-labels.
--
-- The encoding of valid domain names to /presentation form/, performs any
-- required escaping of special characters to ensure lossless round-trip
-- encoding and decoding of valid DNS names, and compatibility with expected
-- external formats.  Valid names are not limited to the letter-digit-hyphen
-- (LDH) syntax of hostnames, all 8-bit characters are allowed in DNS names,
-- subject to the 63-byte limit on /wire form/ label length and 255-byte limit
-- on the /wire form/ domain name (including the terminal empty label).
--
-- Equality and comparison are on the wire-form and case-sensitive.
--
newtype Domain = Domain
    {
    -- | The /wire form/ of a domain name, including the zero-valued
    -- length byte of the terminal empty label.
    shortBytes :: ShortByteString
    } deriving stock TH.Lift
      deriving newtype (Eq, Ord, Hashable)


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

instance Hashable Host where
    hash = hash . canonicalise . fromHost
    hashWithSalt s = hashWithSalt s . canonicalise . fromHost

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
newtype Mbox = Mbox ShortByteString deriving (Eq, Hashable, Ord) via Host

-- | Coerce a 'Domain' to an 'Mbox'.
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
pattern RootDomain <- Domain (SB.length -> 1) where
    RootDomain = rootDomain

-- | Return the wire form of a 'Domain' name as a 'ByteString'
wireBytes :: Domain -> B.ByteString
wireBytes = SB.fromShort . shortBytes

-- | Case-insensitive equality of domain names.
equalWireHost :: Domain -> Domain -> Bool
equalWireHost (Domain sa) (Domain sb)
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
compareWireHost (Domain sa) (Domain sb) = go 0
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

---------------------------------------- Wire-form assembly

-- | Execute a builder to produce a 'Domain'.  Used by the wire-form
-- decoder to turn the @\<prefix\>\<suffix\>@ Builder produced by
-- pointer-following into a 'Domain'; the presentation-form parsers
-- live in "Net.DNSBase.Internal.Domain.Parse8" and write directly
-- into a fresh 'A.MutableByteArray' rather than going via Builder.
buildDomain :: Maybe B.Builder -> Maybe Domain
buildDomain mb = mb >>= \b -> do
    let buf = LB.toStrict $ B.toLazyByteStringWith domainStrat mempty b
    guard $ B.length buf < 256
    pure $! Domain $ SB.toShort buf

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
    , len < 256 = Just $! Domain $ combine len
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
    | SB.any isupper bytes = Domain $ SB.map tolower bytes
    | otherwise = domain


-- | Attempt to prepend the given label to the given domain, provided the label
-- length is 63 bytes or less, and the resulting domain is not too long.
--
consDomain :: ShortByteString -> Domain -> Maybe Domain
consDomain label@(SB.length -> llen)  suffix@(coerce SB.length -> slen) = do
    let len = llen + 1 + slen
    guard $ llen > 0 && llen <= 63 && len < 256
    pure $! Domain $ combine len
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
unconsDomain (Domain sbs)
    | len > 1   = Just (label, Domain suffix)
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
    pure $! Domain $ combine len
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
--     the root NUL is the last byte, and there is no truncation
--     or trailing garbage.
--
-- Suitable for receiving bytes the caller cannot prove
-- well-formed (e.g. labels handed back by a foreign library or
-- another package).  Wire-form bytes that come straight from the
-- decoder in "Net.DNSBase.Decode.Domain" are already validated and
-- do not need to round-trip through this check.
wireToDomain :: ShortByteString -> Maybe Domain
wireToDomain sbs
    | total >= 1, total <= 255, walk 0 = Just (Domain sbs)
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
-- @String -> Either e ShortByteString@; @dnLit@ runs it at compile
-- time, additionally checks the bytes via 'wireToDomain', and
-- embeds the resulting 'Domain' as a constant.  An invalid literal
-- (parser failure /or/ wire-shape failure) becomes a compile-time
-- error.
--
-- The 'dnsbase' library deliberately does not bundle a domain
-- parser; users compose a parser of their choice and pass it in.
-- The natural source of validating parsers is the @idna2008@
-- package.  Note that Template-Haskell staging forbids referring
-- to a same-module top-level binding from inside the splice, so
-- the parser must either be defined in an /imported/ module or
-- bound by a @let@ /inside/ the splice; for a single-call site
-- the latter is the more compact form:
--
-- > import qualified Data.Text as T
-- > import qualified Text.IDNA2008 as I
-- >
-- > example :: Domain
-- > example = $$(let forms = I.idnLabelForms
-- >                  parse = \str -> do
-- >                          let txt = T.pack str
-- >                          (dom, _) <- I.parseDomain forms txt
-- >                          pure $ I.wireBytesShort dom
-- >               in dnLit parse "www.example.org")
--
-- Hoisting the parser into a separate module avoids retyping the
-- @let@ at every literal:
--
-- > -- in MyDomainParsers.hs
-- > strictParser :: String -> Either I.IdnaError ShortByteString
-- > strictParser = fmap (I.wireBytesShort . fst)
-- >              . I.parseDomain I.idnLabelForms . T.pack
-- >
-- > -- in any module that imports MyDomainParsers
-- > example :: Domain
-- > example = $$(dnLit strictParser "www.example.org")
--
-- The emitted splice is a constant 'Domain' value (the wire-form
-- 'ShortByteString' is materialised once from its compile-time
-- @Addr#@ literal on first evaluation); the splice itself runs no
-- runtime IDNA code, and the caller's binary carries no
-- @idna2008@ dependency unless the user imports it themselves.
dnLit :: forall e m. (Show e, MonadFail m, TH.Quote m)
      => (String -> Either e ShortByteString)
      -> String
      -> TH.Code m Domain
dnLit parse s = TH.joinCode case parse s of
    Left e -> fail $ "Invalid domain-name literal " ++ show s
                  ++ ": " ++ show e
    Right b -> case wireToDomain b of
        Just d  -> pure (TH.liftTyped d)
        Nothing -> fail $ "Wire-form invariant violated for literal domain "
                       ++ show s


----------------------------------------------------------------------
-- Mailbox-form parser
----------------------------------------------------------------------

-- | Errors raised by 'parseMbox'.  The @e@ parameter is the error
-- type the caller-supplied domain parser produces; a failure of
-- that parser is surfaced as 'MboxDomainFailed' so the caller can
-- inspect it.  The other constructors describe failures that
-- happen on the dnsbase side, before or after the user's parser
-- runs.
data MboxErr e
    = MboxEmptyLocalpart        -- ^ Empty localpart (e.g. @\"\@example.org\"@).
    | MboxLocalpartTooLong !Int -- ^ Localpart exceeds 63 bytes after escape
                                --   decoding; payload is the actual length.
    | MboxBadEscape !Int        -- ^ Localpart contains a syntactically malformed
                                --   escape (truncated, non-digit in @\\DDD@), or
                                --   an escape that would inject a non-ASCII byte
                                --   (@\\DDD@ with @DDD >= 128@, or @\\C@ with
                                --   the codepoint of @C@ @>= 0x80@), which is
                                --   disallowed in EAI mailboxes.  Payload is the
                                --   input @'Char'@ offset.
    | MboxBadCodepoint !Int     -- ^ Localpart contains a literal surrogate Char
                                --   (@U+D800..U+DFFF@), which UTF-8 cannot encode.
                                --   Payload is the input @'Char'@ offset.
    | MboxCombinedTooLong !Int  -- ^ Combined wire form exceeds 255 bytes; payload
                                --   is the actual length.
    | MboxDomainFailed e        -- ^ The caller-supplied domain parser rejected the
                                --   post-separator text.
    deriving stock (Eq, Show, Functor)

-- | Parse a mailbox-form presentation string into a 'Domain'.  The
-- input is split at the first unescaped @\'\@\'@ if any; otherwise
-- at the first unescaped @\'.\'@; otherwise the entire input is
-- the localpart and the resulting 'Domain' has a single non-root
-- label (matching the existing single-label mailbox-parser
-- behaviour from "Net.DNSBase.Internal.Domain.Parse8").  A
-- separator present but followed by an empty domain part (e.g.
-- @\"postmaster\@\"@ or @\"postmaster.\"@) is treated the same
-- way as if the separator were absent: the localpart is one
-- label, the domain is the root.
--
-- Following EAI semantics (RFC 6532), the localpart's wire bytes
-- are either pure 7-bit ASCII or a well-formed UTF-8 sequence;
-- there is no path to inject a raw non-ASCII octet.
-- Concretely:
--
--   * Literal characters in the source are emitted as their
--     UTF-8 encoding: ASCII chars become one byte, non-ASCII
--     Unicode codepoints become the corresponding 2-, 3-, or
--     4-byte UTF-8 sequence.  Source text like
--     @\"\1074\1080\1082\1090\1086\1088\@example.org\"@
--     therefore round-trips through the wire form as the UTF-8
--     bytes of the user-typed glyphs.  Literal surrogate Chars
--     (@U+D800..U+DFFF@) are rejected with 'MboxBadCodepoint',
--     since UTF-8 cannot encode them.
--   * @\\DDD@ (three ASCII decimal digits, @0..127@) emits the
--     single ASCII byte with that value.  Values @>= 128@ are
--     rejected with 'MboxBadEscape' -- a high-bit raw octet has
--     no place in a pure-ASCII\/pure-UTF-8 localpart.
--   * @\\C@ (any other single character) emits @C@ as a single
--     ASCII byte; @C@'s codepoint must be @< 0x80@.  A @\\C@
--     escape with a non-ASCII codepoint is rejected with
--     'MboxBadEscape' for the same reason.
--
-- The rules above apply only to the /localpart/ -- the first
-- label of the mailbox name.  The post-separator text (if any)
-- is handed verbatim to the caller-supplied domain parser; the
-- domain part has its own validation rules (LDH, IDN, ...)
-- which are entirely the parser's concern.
--
-- The localpart bypasses any label-form rules and may contain
-- arbitrary printable Unicode content, capped at the 63-byte
-- single-label wire-length limit.
--
-- The parser's output is expected to be a wire-form
-- 'ShortByteString' that 'wireToDomain' would accept; the
-- decoded localpart is then prepended as label 0 of the combined
-- 'Domain'.
parseMbox
    :: forall e
    .  (String -> Either e ShortByteString)
    -> String
    -> Either (MboxErr e) Domain
parseMbox parseDom s = do
    sep <- scanMboxSep s
    let (lpStr, mRest) = case sep of
            SepNone   -> (s,            Nothing)
            SepDot i  -> (take i s,     Just (drop (i + 1) s))
            SepAt  i  -> (take i s,     Just (drop (i + 1) s))
    !lpBytes <- decodeLocalpart lpStr
    let !lpLen = SB.length lpBytes
    if  | lpLen == 0   -> Left MboxEmptyLocalpart
        | lpLen > 63   -> Left (MboxLocalpartTooLong lpLen)
        | otherwise    -> do
            !domWire <- case mRest of
                Just rest | not (null rest)
                            -> first MboxDomainFailed (parseDom rest)
                _           -> Right rootWire
            let !combined = SB.singleton (i2w lpLen) <> lpBytes <> domWire
                !total    = SB.length combined
            if total > 255
              then Left (MboxCombinedTooLong total)
              else case wireToDomain combined of
                  Just d  -> Right d
                  Nothing -> Left (MboxCombinedTooLong total)
  where
    !rootWire = SB.singleton 0

-- | The position of the separator selected by 'scanMboxSep'.  An
-- @'\@'@ wins over a @'.'@ regardless of order; @'.'@ is only
-- selected when no @'\@'@ is present.
data MboxSep
    = SepNone
    | SepDot !Int        -- ^ String index of the first unescaped '.'
    | SepAt  !Int        -- ^ String index of the (first) unescaped '@'
    deriving (Eq, Show)

-- | Single-pass scan for the localpart\/domain separator,
-- skipping backslash escapes.
scanMboxSep :: forall e. String -> Either (MboxErr e) MboxSep
scanMboxSep = go 0 SepNone
  where
    go :: Int -> MboxSep -> String -> Either (MboxErr e) MboxSep
    go !_   !acc []         = Right acc
    go !idx !acc (c : cs)
        | c == '@'          = Right (SepAt idx)
        | c == '.'          = case acc of
                                  SepNone -> go (idx + 1) (SepDot idx) cs
                                  _       -> go (idx + 1) acc           cs
        | c == '\\'         = handleEsc idx acc cs
        | otherwise         = go (idx + 1) acc cs

    handleEsc :: Int -> MboxSep -> String -> Either (MboxErr e) MboxSep
    handleEsc !idx !_   []          = Left (MboxBadEscape idx)
    handleEsc !idx !acc (d : cs)
        | Char.isDigit d            = case cs of
            (e : f : cs')
                | Char.isDigit e
                , Char.isDigit f    -> go (idx + 4) acc cs'
            _                       -> Left (MboxBadEscape idx)
        | otherwise                 = go (idx + 2) acc cs

-- | Decode a localpart 'String' into its wire-form bytes
-- (without the length-prefix byte; the caller prepends that
-- after validating the length).
--
-- Following EAI mailbox semantics: the bytes that hit the wire
-- form are either ASCII or a valid UTF-8 sequence; there is no
-- way to inject a raw non-ASCII byte.  Concretely:
--
--   * Literal characters in the source: ASCII chars contribute
--     one byte, non-ASCII Unicode codepoints UTF-8-encode to
--     2\/3\/4-byte sequences.  Surrogate codepoints
--     (@U+D800..U+DFFF@) cannot be UTF-8-encoded and are
--     rejected with 'MboxBadCodepoint'.
--
--   * @\\DDD@ (three ASCII decimal digits) emits the single
--     ASCII byte with that value.  Values @>= 128@ are rejected
--     with 'MboxBadEscape': a non-ASCII octet would not on its
--     own form a valid UTF-8 sequence and would corrupt the
--     well-formedness of the surrounding localpart.
--
--   * @\\C@ (any other single character) emits the codepoint of
--     @C@ as a single ASCII byte; the codepoint must be @< 0x80@.
--     A @\\C@ escape with a non-ASCII codepoint is rejected with
--     'MboxBadEscape' for the same reason as a high @\\DDD@.
decodeLocalpart :: forall e. String -> Either (MboxErr e) ShortByteString
decodeLocalpart s = SB.pack . reverse <$> go 0 [] s
  where
    go :: Int -> [Word8] -> String -> Either (MboxErr e) [Word8]
    go !_   !acc []         = Right acc
    go !idx !acc (c : cs)
        | c == '\\'         = handleEsc idx acc cs
        | otherwise         =
            case utf8Encode idx c of
              Left e   -> Left e
              Right bs -> go (idx + 1) (revPrepend bs acc) cs

    handleEsc :: Int -> [Word8] -> String -> Either (MboxErr e) [Word8]
    handleEsc !idx !_   []          = Left (MboxBadEscape idx)
    handleEsc !idx !acc (d : cs)
        | Char.isDigit d            = case cs of
            (e : f : cs')
                | Char.isDigit e
                , Char.isDigit f    ->
                    let !n =   100 * Char.digitToInt d
                            +   10 * Char.digitToInt e
                            +        Char.digitToInt f
                    in if n < 0x80
                         then go (idx + 4) (fromIntegral n : acc) cs'
                         else Left (MboxBadEscape idx)
            _                       -> Left (MboxBadEscape idx)
        | n <- Char.ord d
        , n < 0x80                  = go (idx + 2) (fromIntegral n : acc) cs
        | otherwise                 = Left (MboxBadEscape idx)

    -- Prepend bytes in reverse so the eventual final 'reverse'
    -- restores natural UTF-8 byte order in the packed result.
    revPrepend :: [Word8] -> [Word8] -> [Word8]
    revPrepend []     !acc = acc
    revPrepend (b:bs) !acc = revPrepend bs (b : acc)

    -- UTF-8-encode a literal 'Char' into its natural-order byte
    -- sequence.  Surrogate codepoints (@U+D800..U+DFFF@) cannot
    -- be UTF-8-encoded and produce 'MboxBadCodepoint'; all other
    -- valid Unicode codepoints (0..0x10FFFF) succeed.
    utf8Encode :: Int -> Char -> Either (MboxErr e) [Word8]
    utf8Encode !idx c
        | n < 0x80     = Right [fromIntegral n]
        | n < 0x800    = Right
              [ fromIntegral (0xC0 .|. (n `shiftR` 6))
              , fromIntegral (0x80 .|. (n .&. 0x3F)) ]
        | n >= 0xD800
        , n <  0xE000  = Left (MboxBadCodepoint idx)
        | n < 0x10000  = Right
              [ fromIntegral (0xE0 .|. (n `shiftR` 12))
              , fromIntegral (0x80 .|. ((n `shiftR` 6) .&. 0x3F))
              , fromIntegral (0x80 .|. (n .&. 0x3F)) ]
        | otherwise    = Right
              [ fromIntegral (0xF0 .|. (n `shiftR` 18))
              , fromIntegral (0x80 .|. ((n `shiftR` 12) .&. 0x3F))
              , fromIntegral (0x80 .|. ((n `shiftR` 6) .&. 0x3F))
              , fromIntegral (0x80 .|. (n .&. 0x3F)) ]
      where
        !n = Char.ord c


-- | Template-Haskell typed splice for a compile-time mailbox
-- literal.  Uses 'parseMbox' internally: the localpart is parsed
-- locally with DNS-style escapes, and the post-separator domain
-- text is passed to the caller-supplied parser.  An invalid
-- literal (localpart failure /or/ domain-parser failure /or/
-- combined-length failure) becomes a compile-time error.
--
-- The parser argument has the same shape as 'dnLit'\'s:
-- @String -> Either e ShortByteString@.  The user can therefore
-- pass exactly the same parser they pass to 'dnLit' (typically a
-- composition with @idna2008@), and the mailbox literal inherits
-- the same IDN policy for the domain portion of the name.  See
-- 'dnLit' for the standard idioms.
mbLit :: forall e m. (Show e, MonadFail m, TH.Quote m)
      => (String -> Either e ShortByteString)
      -> String
      -> TH.Code m Domain
mbLit parse s = TH.joinCode case parseMbox parse s of
    Left e  -> fail $ "Invalid mailbox literal " ++ show s
                   ++ ": " ++ show e
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
toLabels (Domain sbs) = go 0
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
commonSuffix (Domain s1) (Domain s2) = go (min len1 len2) 0 0
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
        tailSlice = Domain $
            baToShortByteString $ A.cloneByteArray ba1 (len1 - sz) sz


-- | Encode a 'Domain' name without name compression
mbWireForm :: Domain -> SizedBuilder
mbWireForm d = mbShortByteString (shortBytes d)
{-# INLINE mbWireForm #-}

---------------------------------------- Wire -> Presentation

-- | Build the standard (dot-terminated) /presentation form/ of 'Domain'.
presentDomain :: Domain -> Builder -> Builder
presentDomain = fromWire dotB W_dot

-- | Build the /presentation form/ of a 'Domain' without a trailing dot.
-- The root domain is nevertheless presented as a single @.@ byte.
presentHost :: Domain -> Builder -> Builder
presentHost = toCanonical W_dot

-- | Build an ad hoc /mailbox form/ of a 'Domain', without a trailing dot,
-- and with '@' as the first label separator.
presentMbox :: Domain -> Builder -> Builder
presentMbox = toCanonical W_at

-- | Build a presentation form.
fromWire :: (Builder -> Builder) -> Word8 -> Domain -> Builder -> Builder
fromWire dterm sep0 (B.uncons . wireBytes -> ht) k
    | Just (len, bs) <- ht = go sep0 len bs
    | otherwise            = impossible
  where
    go :: Word8 -> Word8 -> ByteString -> Builder
    go _   0   _     = dotB k
    go sep len bytes =
        let (label, suffix) = B.splitAt (fromEnum len) bytes
         in case B.uncons suffix of
                Just (slen, sbytes)
                    | slen > 0 -> presentDomainLabel sep label
                                  . presentByte sep
                                  $ go W_dot slen sbytes
                _   -> presentDomainLabel W_dot label $ dterm k

-- | Build a canonical presentation form (folded to lower case)
toCanonical :: Word8 -> Domain -> Builder -> Builder
toCanonical sep0 (B.uncons . wireBytes -> ht) k
    | Just (len, bs) <- ht = go sep0 len bs
    | otherwise            = impossible
  where
    go :: Word8 -> Word8 -> ByteString -> Builder
    go _   0   _     = dotB k
    go sep len bytes =
        let (label, suffix) = B.splitAt (fromEnum len) bytes
         in canon sep label
            $ case B.uncons suffix of
               Just (slen, sbytes)
                   | slen > 0 -> presentByte sep (go W_dot slen sbytes)
               _              -> k
      where
        canon W_dot = presentHostLabel W_dot
        canon w     = presentDomainLabel w

---------------------------------------- Util

-- | Most domain names are short, use small buffers, but no need to make them
-- too tight since we ultimately copy again into a short bytestring.
domainStrat :: B.AllocationStrategy
domainStrat = B.untrimmedStrategy 32 128

pattern W_dot    :: Word8;      pattern W_dot    = 0x2e
pattern W_at     :: Word8;      pattern W_at     = 0x40

dotB :: Builder -> Builder
dotB = presentByte W_dot

{-# INLINE w2i #-}
w2i :: Word8 -> Int
w2i = fromIntegral

{-# INLINE i2w #-}
i2w :: Int -> Word8
i2w = fromIntegral

-- | Upper case ASCII letter?
{-# INLINE isupper #-}
isupper :: Word8 -> Bool
isupper w = (w - 0x41 < 26)

-- | Map upper case ASCII to lower case.
{-# INLINE tolower #-}
tolower :: Word8 -> Word8
tolower w | isupper w = w + 32
tolower w = w
