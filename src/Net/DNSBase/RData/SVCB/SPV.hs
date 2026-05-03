{-|
Module      : Net.DNSBase.RData.SVCB.SPV
Description : Concrete value types for SVCB / HTTPS service parameters
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

One 'KnownSVCParamValue' instance per standardised service
parameter key.  Each type corresponds to a 'SVCParamKey' from
the IANA registry and carries the value payload for that key
in a form suited to the application that consumes it (a port
as 'Word16', address hints as a 'NonEmpty' of 'IPv4' / 'IPv6',
and so on).

An unknown key falls through to
'Net.DNSBase.RData.SVCB.OpaqueSPV', which preserves the raw wire
bytes.  Applications register additional typed values at runtime
via 'Net.DNSBase.Resolver.extendRRwithType' on the @SVCB@ or
@HTTPS@ RR type — see "Net.DNSBase.Extensible" for a worked
example.
-}

module Net.DNSBase.RData.SVCB.SPV
    ( SPV_mandatory(SPV_MANDATORY)
    , SPV_alpn(..)
    , SPV_ndalpn(..)
    , SPV_port(..)
    , SPV_ipv4hint(..)
    , SPV_ipv6hint(..)
    , SPV_ech(..)
    , SPV_dohpath(..)
    , SPV_docpath(..)
    , SPV_tlsgroups(..)
    , SPV_pvd(..)
    ) where

import qualified Data.ByteString.Short as SB
import qualified Data.List.NonEmpty as NE
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Unsafe as T
import Data.Set (Set)

import Net.DNSBase.Internal.Util

import Net.DNSBase.Bytes
import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.NonEmpty
import Net.DNSBase.Present
import Net.DNSBase.RData.SVCB.SPVList
import Net.DNSBase.RData.SVCB.SVCParamKey
import Net.DNSBase.RData.SVCB.SVCParamValue
import Net.DNSBase.Text

-- | The @mandatory@ service parameter
-- ([RFC 9460 section 8](https://datatracker.ietf.org/doc/html/rfc9460#section-8))
-- — the set of additional 'SVCParamKey' codes a client must
-- recognise to make sense of this RR, on top of any keys that
-- are automatically mandatory for the application protocol.  A
-- client that does not understand all the listed keys must
-- ignore the RR.
--
-- The set may not be empty on the wire (an empty list is
-- encoded as the parameter being absent) and may hold at most
-- 32767 keys.  The constructor is not exported; build instances
-- via 'fromNonEmptyList' or by combining values with their
-- 'Semigroup' instance.
newtype SPV_mandatory = SPV_mandatory (Set SVCParamKey)
    deriving (Eq, Semigroup)

-- | One-way pattern exposing the underlying key set for lookups.
-- Construction is available only via 'fromNonEmptyList' or via the
-- 'Semigroup' instance.
pattern SPV_MANDATORY :: Set SVCParamKey -- ^ The keys as a 'Set'
                      -> SPV_mandatory
pattern SPV_MANDATORY s <- SPV_mandatory s
{-# COMPLETE SPV_MANDATORY #-}

instance Show SPV_mandatory where
    showsPrec p (SPV_mandatory s) = showsP p $
        showString "fromNonEmptyList @SPV_mandatory "
        . shows' (NE.fromList $ Set.toList s)

instance IsNonEmptyList SPV_mandatory where
    type Item1 SPV_mandatory = SVCParamKey
    fromNonEmptyList = coerce . Set.fromList . NE.toList
    toNonEmptyList = NE.fromList . Set.toList . coerce

-- | Wire-form order
instance Ord SPV_mandatory where
    SPV_MANDATORY a `compare` SPV_MANDATORY b =
        comparing Set.size a b
        <> comparing Set.toList a b

instance Presentable SPV_mandatory where
    present (SPV_MANDATORY (NE.fromList . Set.toList -> key :| keys)) =
        present MANDATORY
        . pfst key
        . flip (foldr pnxt) keys
      where
        pfst = presentCharSep '='
        pnxt = presentCharSep ','

instance KnownSVCParamValue SPV_mandatory where
    spvKey _ = MANDATORY
    encodeSPV (SPV_MANDATORY (coerce -> ks)) = do
        when (Set.size ks > 0x7fff) do failWith CantEncode
        putSizedBuilder $ foldMap mbWord16
                        $ coerce @[SVCParamKey] @[Word16] $ Set.toList ks

    -- | Decode the mandatory key list.
    -- XXX: Does not yet enforce ascending order, non-duplication,
    -- self-exclusion, or exclusion of automatically mandatory keys, all of
    -- which are required by the SVCB draft:
    -- <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-12#section-2.2>,
    -- <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-12#section-8>
    --
    -- The resulting keyset will however be de-duplicated and ordered.
    --
    decodeSPV _ len = do
        k <- mkKey <$> get16
        ks <- getFixedWidthSequence 2 (mkKey <$> get16) (len - 2)
        pure $ SVCParamValue $ mkMandatory $ Set.fromList $ k : ks
      where
        mkKey :: Word16 -> SVCParamKey
        mkKey = coerce
        mkMandatory :: Set SVCParamKey -> SPV_mandatory
        mkMandatory = coerce

-- | The @alpn@ service parameter
-- ([RFC 9460 section 7.1](https://datatracker.ietf.org/doc/html/rfc9460#section-7.1))
-- — the set of Application-Layer Protocol Negotiation
-- ([RFC 7301](https://datatracker.ietf.org/doc/html/rfc7301))
-- protocol identifiers this service endpoint supports.  Together
-- with 'SPV_ndalpn' it defines the SVCB ALPN set: by default the
-- scheme's protocol is implicitly included, and 'SPV_ndalpn'
-- suppresses that default.
newtype SPV_alpn = SPV_ALPN (NonEmpty ShortByteString)
    deriving (Eq, Show)

instance Ord SPV_alpn where
    (SPV_ALPN as) `compare` (SPV_ALPN bs) =
        comparing len as bs
        <> comparing (coerce @(NonEmpty ShortByteString) @(NonEmpty DnsText)) as bs
      where
        len xs = foldl' (\a x -> a + 1 + SB.length x) 0 xs

instance Presentable SPV_alpn where
    present (SPV_ALPN vs) =
        present ALPN . present '=' . presentSPVList vs

instance KnownSVCParamValue SPV_alpn where
    spvKey _ = ALPN
    encodeSPV (SPV_ALPN vs) =
        putSizedBuilder $ foldMap (mbShortByteStringLen8 . coerce) vs
    decodeSPV _ len = do
        pos0 <- getPosition
        a <- getShortByteStringLen8
        pos1 <- getPosition
        let used = pos1 - pos0
        as <- getVarWidthSequence getShortByteStringLen8 (len - used)
        pure $ SVCParamValue . SPV_ALPN $ a :| as

-- | The @no-default-alpn@ service parameter
-- ([RFC 9460 section 7.1](https://datatracker.ietf.org/doc/html/rfc9460#section-7.1))
-- — a value-less flag that suppresses the scheme's default ALPN
-- from the SVCB ALPN set.  Meaningful only alongside an explicit
-- 'SPV_alpn' that supplies a replacement protocol list.
data SPV_ndalpn = SPV_NDALPN
    deriving (Eq, Ord, Show)

instance Presentable SPV_ndalpn where
    present _ = present NODEFAULTALPN

instance KnownSVCParamValue SPV_ndalpn where
    spvKey _ = NODEFAULTALPN
    encodeSPV _ = pure ()
    decodeSPV _ _ = pure $ SVCParamValue SPV_NDALPN

-- | The @port@ service parameter
-- ([RFC 9460 section 7.2](https://datatracker.ietf.org/doc/html/rfc9460#section-7.2))
-- — overrides the scheme's default TCP or UDP port for reaching
-- this service endpoint.
newtype SPV_port = SPV_PORT Word16
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

instance Presentable SPV_port where
    present (SPV_PORT port) =
        present PORT
        . presentCharSep '=' port

instance KnownSVCParamValue SPV_port where
    spvKey _ = PORT
    encodeSPV = put16 . coerce
    decodeSPV _ _ = SVCParamValue . SPV_PORT <$> get16

-- | The @ipv4hint@ service parameter
-- ([RFC 9460 section 7.3](https://datatracker.ietf.org/doc/html/rfc9460#section-7.3))
-- — a non-empty list of IPv4 addresses for this service endpoint
-- that a client may use to start a connection in parallel with
-- an authoritative @A@ lookup.  Hints are advisory; clients
-- should still validate them against authoritative address
-- records when they arrive.
newtype SPV_ipv4hint = SPV_IPV4HINT (NonEmpty IPv4)
    deriving (Eq)

instance Show SPV_ipv4hint where
    showsPrec p (SPV_IPV4HINT ips) = showsP p $
        showString "SPV_IPV4HINT "
        . shows' (fmap show ips)

instance Ord SPV_ipv4hint where
    compare (SPV_IPV4HINT a) (SPV_IPV4HINT b) =
        comparing NE.length a b <> compare a b

instance Presentable SPV_ipv4hint where
    present (SPV_IPV4HINT (a :| as)) =
        present IPV4HINT
        . pfst a
        . flip (foldr pnxt) as
      where
        pfst = presentCharSep '='
        pnxt = presentCharSep ','

instance KnownSVCParamValue SPV_ipv4hint where
    spvKey _ = IPV4HINT
    encodeSPV (SPV_IPV4HINT ips) = putSizedBuilder $ foldMap mbIPv4 ips
    decodeSPV _ len = do
        ip  <- getIPv4
        ips <- getFixedWidthSequence 4 getIPv4 (len - 4)
        return $ SVCParamValue $ SPV_IPV4HINT (ip :| ips)

-- | The @ipv6hint@ service parameter
-- ([RFC 9460 section 7.3](https://datatracker.ietf.org/doc/html/rfc9460#section-7.3))
-- — the IPv6 counterpart of 'SPV_ipv4hint': a non-empty list of
-- IPv6 addresses to try in parallel with the authoritative
-- @AAAA@ lookup.
newtype SPV_ipv6hint = SPV_IPV6HINT (NonEmpty IPv6)
    deriving (Eq)

instance Show SPV_ipv6hint where
    showsPrec p (SPV_IPV6HINT ips) = showsP p $
        showString "SPV_IPV6HINT "
        . shows' (fmap show ips)

instance Ord SPV_ipv6hint where
    compare (SPV_IPV6HINT a) (SPV_IPV6HINT b) =
        comparing NE.length a b <> compare a b

instance Presentable SPV_ipv6hint where
    present (SPV_IPV6HINT (a :| as)) =
        present IPV6HINT
        . pfst a
        . flip (foldr pnxt) as
      where
        pfst = presentCharSep '='
        pnxt = presentCharSep ','

instance KnownSVCParamValue SPV_ipv6hint where
    spvKey _ = IPV6HINT
    encodeSPV (SPV_IPV6HINT ips) = putSizedBuilder $ foldMap mbIPv6 ips
    decodeSPV _ len = do
        ip  <- getIPv6
        ips <- getFixedWidthSequence 16 getIPv6 (len - 16)
        return $ SVCParamValue $ SPV_IPV6HINT (ip :| ips)

-- | The @ech@ service parameter
-- ([RFC9848, Section 3](https://datatracker.ietf.org/doc/html/rfc9848#section-3))
-- — an Encrypted Client Hello (ECH) configuration list.
-- Presented as a base64-encoded value.
newtype SPV_ech = SPV_ECH ShortByteString
    deriving (Eq, Show)

instance Ord SPV_ech where
    compare = dnsTextCmp

instance Presentable SPV_ech where
    present (SPV_ECH c) = present ECH . presentCharSep @Bytes64 '=' (coerce c)

instance KnownSVCParamValue SPV_ech where
    spvKey _ = ECH
    encodeSPV (SPV_ECH c) = putShortByteString $ coerce c
    decodeSPV _ 0 = failSGet "Invalid empty 'ech' ParamKey value"
    decodeSPV _ len
        | len < 4 = failSGet "'ech' ParamKey value too short"
        | otherwise = SVCParamValue . SPV_ECH <$> getShortNByteString len

-- | The @dohpath@ service parameter
-- ([RFC 9461](https://datatracker.ietf.org/doc/html/rfc9461#name-new-svcparamkey-dohpath))
-- — a URI template (UTF-8) advertising the DNS-over-HTTPS
-- endpoint at this service.  Typically seen on resolver-discovery
-- answers to queries for @_dns.resolver.arpa@ or on explicit
-- queries to a specific operator's resolver.
newtype SPV_dohpath = SPV_DOHPATH T.Text
    deriving (Eq, Show)

instance Ord SPV_dohpath where
    compare (SPV_DOHPATH a) (SPV_DOHPATH b) =
        comparing T.lengthWord8 a b
        <> compare a b

instance Presentable SPV_dohpath where
    present (SPV_DOHPATH uri) =
        present DOHPATH . presentCharSep @DnsUtf8Text '=' (coerce uri)

instance KnownSVCParamValue SPV_dohpath where
    spvKey _ = DOHPATH
    encodeSPV (SPV_DOHPATH uri) = putUtf8Text uri
    decodeSPV _ = SVCParamValue . SPV_DOHPATH <.> getUtf8Text

-- | The @docpath@ service parameter
-- ([RFC 9953 section 8.2](https://datatracker.ietf.org/doc/html/rfc9953#section-8.2))
-- — the absolute path to the DNS-over-CoAP (DoC) resource at this
-- service endpoint, represented as a list of path segments.  An
-- empty list denotes the root path @\"/\"@ (on the wire: a
-- zero-length SvcParamValue).
--
-- Each segment is 1..255 octets per the RFC ABNF; the wire-form
-- decoder rejects zero-length segments.  Presentation form is a
-- comma-separated list of segments using the standard RFC 9460
-- Appendix A.1 quoting and escaping rules, identical to those of
-- 'SPV_alpn'.
newtype SPV_docpath = SPV_DOCPATH [ShortByteString]
    deriving (Eq, Show)

-- | Wire-form canonical order: by total wire length first, then
-- by the segment-list 'DnsText' ordering.
instance Ord SPV_docpath where
    (SPV_DOCPATH as) `compare` (SPV_DOCPATH bs) =
        comparing wireLen as bs
        <> comparing (coerce @[ShortByteString] @[DnsText]) as bs
      where
        wireLen = foldl' (\a x -> a + 1 + SB.length x) 0

instance Presentable SPV_docpath where
    present (SPV_DOCPATH vs) =
        present DOCPATH . present '=' . presentCSVList vs

instance KnownSVCParamValue SPV_docpath where
    spvKey _ = DOCPATH
    encodeSPV (SPV_DOCPATH vs) =
        putSizedBuilder $ foldMap mbShortByteStringLen8 vs
    decodeSPV _ len = do
        vs <- getVarWidthSequence segment len
        pure $ SVCParamValue $ SPV_DOCPATH vs
      where
        segment = do
            seg <- getShortByteStringLen8
            when (SB.null seg) $ failSGet "Empty docpath segment"
            pure seg

-- | The @tls-supported-groups@ service parameter
-- ([draft-ietf-tls-key-share-prediction-04 section 5](https://datatracker.ietf.org/doc/html/draft-ietf-tls-key-share-prediction-04#section-5))
-- — a non-empty list of TLS Named Group codepoints (the
-- [IANA TLS Supported Groups registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8))
-- that the service supports.  Clients can use this hint to
-- predict an acceptable key share, reducing the chance of a
-- HelloRetryRequest round-trip.
--
-- The wire form is a non-empty sequence of 16-bit codepoints in
-- network byte order; the decoder rejects an empty value.  The
-- presentation form is a comma-separated list of decimal
-- integers and forbids zone-file escape sequences (per the
-- draft).  Duplicates are flagged as a syntax error by the
-- specification but are not currently rejected by either the
-- encoder or the decoder — callers are expected to feed in a
-- duplicate-free list, in their preferred order (the spec does
-- not impose canonical ordering on the wire).
newtype SPV_tlsgroups = SPV_TLSGROUPS (NonEmpty Word16)
    deriving (Eq, Show)

-- | Wire-form canonical order: by length first, then elementwise.
instance Ord SPV_tlsgroups where
    (SPV_TLSGROUPS as) `compare` (SPV_TLSGROUPS bs) =
        comparing NE.length as bs <> compare as bs

instance Presentable SPV_tlsgroups where
    present (SPV_TLSGROUPS (g :| gs)) =
        present TLSGROUPS
        . pfst g
        . flip (foldr pnxt) gs
      where
        pfst = presentCharSep '='
        pnxt = presentCharSep ','

instance KnownSVCParamValue SPV_tlsgroups where
    spvKey _ = TLSGROUPS
    encodeSPV (SPV_TLSGROUPS gs) = putSizedBuilder $ foldMap mbWord16 gs
    decodeSPV _ len = do
        g  <- get16
        gs <- getFixedWidthSequence 2 get16 (len - 2)
        pure $ SVCParamValue $ SPV_TLSGROUPS (g :| gs)

-- | The @pvd@ service parameter
-- ([draft-ietf-intarea-proxy-config-14 section 7.5](https://datatracker.ietf.org/doc/html/draft-ietf-intarea-proxy-config-14#section-7.5))
-- — a value-less flag that announces the host supports
-- Provisioning Domain discovery via the well-known PvD URI.  Its
-- presence in an SVCB or HTTPS RR signals that a client MAY
-- fetch PvD Additional Information from
-- @https:\/\/host\/.well-known\/pvd@.  Per the draft, the wire
-- value MUST be empty; the presentation form is just the bare
-- key name with no @\'=\'@.
data SPV_pvd = SPV_PVD
    deriving (Eq, Ord, Show)

instance Presentable SPV_pvd where
    present _ = present PVD

instance KnownSVCParamValue SPV_pvd where
    spvKey _ = PVD
    encodeSPV _ = pure ()
    decodeSPV _ _ = pure $ SVCParamValue SPV_PVD
