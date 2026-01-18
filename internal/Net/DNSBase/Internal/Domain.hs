{-# LANGUAGE
    RecordWildCards
  , TemplateHaskell
  #-}

module Net.DNSBase.Internal.Domain
    ( -- ** Domain name data type
      Domain(RootDomain)
    , DnsTriple(..)
    , Host
    , fromHost
    , toHost
    , Mbox
    , fromMbox
    , toMbox
    -- ** Domain name literals
    , dnLit
    , mbLit
    -- ** Conversions
    -- *** From presentation form
    , parseDomain
    , parseMbox
    , strToDomain
    , strToMbox
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
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Short as SB
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Unsafe as B
import qualified Data.Char as Ch
import qualified Data.List as L
import qualified Data.Primitive.ByteArray as A
import qualified Data.String as S
import qualified Language.Haskell.TH.Syntax as TH
import qualified Language.Haskell.TH.Lib as TH
import Control.Monad.Trans.RWS.CPS (RWST, runRWST, gets, put, modify, tell)
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
    } deriving newtype (Eq, Ord, Hashable)


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

-- | Run-time conversion from presentation form 'String' literals, raises
-- run-time errors for invalid inputs.
instance S.IsString Domain where
    fromString = \s -> case safePack s >>= parseDomain of
        Just dn -> dn
        Nothing -> error $ "Malformed domain name: " ++ s

-- | Template-Haskell splice for literal 'Domain' names that are validated and
-- converted from /presentation form/ to /wire form/ at compile-time.  Example:
--
-- > domain :: Domain
-- > domain = $$(dnLit "example.org")
--
dnLit :: forall m. (MonadFail m, TH.Quote m) => String -> TH.Code m Domain
dnLit s = TH.liftCode $ fmap TH.TExp $ case safePack s >>= parseDomain of
    Just dn -> TH.appE (TH.conE 'Domain)
                       (TH.appE (TH.varE 'SB.toShort)
                                (TH.lift (wireBytes dn)))
    Nothing -> fail "Invalid domain-name literal"

-- | Template-Haskell splice for literal mailbox names that are validated and
-- converted from /presentation form/ to /wire form/ at compile-time.  Example:
--
-- > mbox :: Domain
-- > mbox = $$(mbLit "hostmaster@example.org")
--
mbLit :: (TH.Quote m, MonadFail m) => String -> TH.Code m Domain
mbLit s = TH.liftCode $ fmap TH.TExp $ case safePack s >>= parseMbox of
    Just dn -> TH.appE (TH.conE 'Domain)
                       (TH.appE (TH.varE 'SB.toShort)
                                (TH.lift (wireBytes dn)))
    Nothing -> fail "Invalid mailbox-name literal"

-- | Attempt to parse an input 'String' in /presentation form/ as a domain
-- name. Invalid (including overly-long) input returns 'Nothing'.
strToDomain :: String -> Maybe Domain
strToDomain = safePack >=> parseDomain
-- XXX: make this do punycode conversion
-- TODO: also add a 'Text' version

-- | Attempt to parse an input 'String' email address as a domain name.
-- Invalid (including overly-long) input returns 'Nothing'.  The entire
-- localpart becomes the first label of the domain.
strToMbox :: String -> Maybe Domain
strToMbox = safePack >=> parseMbox
-- XXX: make this do punycode conversion
-- TODO: also add a 'Text' version

---------------------------------------- Presenation -> Domain

-- | Attempt to parse an input 'ByteString' in /presentation form/ as a
-- domain name.  Invalid (including overly-long) input returns 'Nothing'.
parseDomain :: B.ByteString -> Maybe Domain
parseDomain = buildDomain . domainParser True mempty

-- | Attempt to parse an input 'ByteString' in /presentation form/ as a mailbox
-- name.  This is most commonly encountered in the /rname/ of @SOA@ records.
-- Invalid (including overly-long) input returns 'Nothing'.
--
-- The first label, is conceptually the local part of an email address, and may
-- contain internal periods that are not label separators.  Therefore, the
-- /presentation form/ of a mailbox name with at least two labels uses the
-- @\'\@\'@ character as the separator between the first and second labels,
-- and any @\'.\'@ characters in the first label are not escaped.  Except for the
-- empty (root) domain no terminal @\'.\'@ is appended.  The standard @\'.\'@
-- separator is used between the second and any subsequent labels.
--
-- The traditional format with all labels separated by dots is also accepted,
-- but encoding from /wire form/ always uses @\'\@\'@ between the first
-- label and the domain-part of the mailbox name.  Therefore, literal @\'.\'@
-- characters must be escaped in the any single-label mailbox name.  Examples:
--
-- @
-- hostmaster\@example.org  -- First label is: @hostmaster@
-- john.smith\@examle.com   -- First label is: @john.smith@
-- single\\.label           -- Dots are escaped in single-label mailbox names
-- @
--
parseMbox :: ByteString -> Maybe Domain
parseMbox = buildDomain . mboxParser mempty

-- | Execute a builder to produce a 'Domain'.
buildDomain :: Maybe B.Builder -> Maybe Domain
buildDomain mb = mb >>= \b -> do
    let buf = LB.toStrict $ B.toLazyByteStringWith domainStrat mempty b
    guard $ B.length buf < 256
    pure $! Domain $ SB.toShort buf

---------------------------------------- Presentation -> Builder

-- | Accumulate a builder for a 'Domain' from an input 'ByteString' in
-- /presentation form/.
domainParser :: Bool -> B.Builder -> ByteString -> Maybe B.Builder
domainParser top acc bytes = runRWST (doLabel bytes) () 0 >>= \case
    (suff, len, lb)
        | len > 0
          -> if | not $ B.null suff
                  -- Recurse for the remaining labels
                  -> domainParser False (dadd acc len lb) suff
                | otherwise
                  -- Append top-level and root labels
                  -> pure $ dadd acc len lb <> B.word8 0
        | top && B.null suff
          -- Add root label
          -> pure $ acc <> B.word8 0
        | otherwise
          -- Invalid non-final empty label
          -> mzero
  where
    doLabel dom = do
        let (plain, rest) = B.break special dom
            plen = B.length plain
        guard $ plen <= 63
        ladd plen
        tell (B.byteString plain)
        case B.uncons rest of
            Nothing         -> pure rest
            Just (e, suff)
               | W_bSlash <- e -> ladd 1 >> unescLabel suff >>= doLabel
               | otherwise     -> pure suff
      where
        special = \case { W_dot -> True; W_bSlash -> True; _ -> False }

    ladd :: Int -> RWST () B.Builder Int Maybe ()
    ladd i = gets (+ i) >>= \ !l -> guard (l <= 63) >> put l

unescLabel :: ByteString -> RWST () B.Builder s Maybe ByteString
unescLabel eseq = do
    (w, suff) <- lift $ B.uncons eseq
    if | d1 <- fromEnum $ w - W_0
       , d1 <= 9   -> undec d1 suff >> pure (B.drop 2 suff)
       | otherwise -> tell (B.word8 w) >> pure suff
  where
    undec d1 suff = do
        guard $ B.length suff >= 2
        let d2 = fromEnum $ B.unsafeIndex suff 0 - W_0
            d3 = fromEnum $ B.unsafeIndex suff 1 - W_0
            n  = 100 * d1 + 10 * d2 + d3
        guard $ d2 <= 9 && d3 <= 9 && n <= 255
        tell (B.word8 $ toEnum n)

dadd :: B.Builder -> Int -> B.Builder -> B.Builder
dadd acc l lb = acc <> B.word8 (toEnum l) <> lb

data PState = PState { psllen :: Int, psmbox :: Bool }
ps0 :: PState
ps0 = PState { psllen = 0, psmbox = False }

-- | Accumulate a builder for an 'Domain' from an input 'ByteString' in mailbox
-- form.  The separator between the first and second labels can be /either/ an
-- @\@@ or @.@ character.  In the former case, literal dots in the first label
-- do not need to be escaped with a backslash.  When no @\@@ is found between
-- the first two non-empty labels, the input is reparsed as a regular domain
-- name.
--
mboxParser :: B.Builder -> ByteString -> Maybe B.Builder
mboxParser acc bytes = runRWST (doLabel bytes) () ps0 >>= \case
    (suff, ps, lb)
        | False <- psmbox ps
          -- Found no bare '@', reparse as a domain
          -> domainParser True acc bytes
        | len <- psllen ps
          -> if | B.null suff
                  -> if | len > 0
                          -- Explicit root domain part
                          -> dadd acc len lb <> B.word8 0 <$ guard (len <= 63)
                        | otherwise
                          -> pure $ acc <> B.word8 0
                | len > 0
                  -- Recurse for the remaining (domain!) labels
                  -> do guard (len <= 63)
                        domainParser True (dadd acc len lb) suff
                | otherwise
                  -- Invalid empty first and non-final label
                  -> mzero
  where
    doLabel dom = do
        let (plain, rest) = B.break special dom
            plen = B.length plain
        ladd plen
        tell (B.byteString plain)
        if | plen == B.length dom  -> pure B.empty
           | Just (e, suff) <- B.uncons rest
             -> if | W_bSlash <- e -> ladd 1 >> unescLabel suff >>= doLabel
                   | otherwise     -> suff <$ modify \s -> s {psmbox = True}
           | otherwise             -> pure B.empty
      where
        special = \case { W_at -> True; W_bSlash -> True; _ -> False }

    ladd :: Int -> RWST () B.Builder PState Maybe ()
    ladd i = gets id >>= \ !PState{..} -> let !l = psllen+i
                                           in put PState {psllen = l, ..}

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


-- | Given a 'Domain/, return its label count.  The root domain has zero labels.
--
-- >>> labelCount $$(dnLit "example.org")
-- 2
--
-- >>> toLabels $$(mbLit "first.last@example.org")
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
-- >>> toLabels $$(dnLit "example.org")
-- ["example","org"]
--
-- >>> toLabels $$(mbLit "first.last@example.org")
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
-- >>> revLabels $$(dnLit "example.org")
-- ["org","example"]
--
-- >>> revLabels $$(mbLit "first.last@example.org")
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
pattern W_0      :: Word8;      pattern W_0      = 0x30
pattern W_at     :: Word8;      pattern W_at     = 0x40
pattern W_bSlash :: Word8;      pattern W_bSlash = 0x5c

dotB :: Builder -> Builder
dotB = presentByte W_dot

-- | Is the input 'String' composed only of characters in [0,255]
safePack :: String -> Maybe ByteString
safePack s@(all ((<= 0xff) . Ch.ord) -> True) = Just $ C8.pack s
safePack _                                    = Nothing

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
