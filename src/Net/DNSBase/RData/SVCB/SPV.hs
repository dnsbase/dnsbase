module Net.DNSBase.RData.SVCB.SPV
    ( SPV_mandatory(SPV_MANDATORY)
    , SPV_alpn(..)
    , SPV_ndalpn(..)
    , SPV_port(..)
    , SPV_ipv4hint(..)
    , SPV_ipv6hint(..)
    , SPV_ech(..)
    , SPV_dohpath(..)
    ) where

import qualified Data.ByteString.Short as SB
import qualified Data.List.NonEmpty as NE
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Unsafe as T
import Data.Foldable (foldl')
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

-- | [mandatory](https://datatracker.ietf.org/doc/html/rfc9460#section-7.4)
-- This @SVCB@ parameter is used to indicate any mandatory (to process when
-- present) keys for this RR, in addition to any automatically mandatory (for
-- the application protocol) keys that are present.  Keys listed here MUST
-- be present in the @SVCB@ parameter list.
--
-- Note: The set of mandatory keys cannot be empty, and can't hold more than
-- 32767 keys.
newtype SPV_mandatory = SPV_mandatory (Set SVCParamKey)
    deriving (Typeable, Eq, Semigroup)

-- | One-way pattern exposing the underlying key set for lookups.
-- Construction is available only via 'fromNonEmptyList' or via the
-- 'Semigroup' instance.
pattern SPV_MANDATORY :: Set SVCParamKey -> SPV_mandatory
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
    spvKey = MANDATORY
    encodeSPV (SPV_MANDATORY (coerce -> ks)) = do
        let n = Set.size ks
        when (n > 0x7fff) do failWith CantEncode
        put16 (fromIntegral $ 2 * Set.size ks)
        mapM_ put16 $ coerce @[SVCParamKey] @[Word16] $ Set.toList ks

    -- | Decode the mandatory key list.
    -- XXX: Does not yet enforce ascending order, non-duplication,
    -- self-exclusion, or exclusion of automatically mandatory keys, all of
    -- which are required by the SVCB draft:
    -- <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-12#section-2.2>,
    -- <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-12#section-8>
    --
    -- The resulting keyset will however be de-duplicated and ordered.
    --
    decodeSPV len = do
        k <- mkKey <$> get16
        ks <- getFixedWidthSequence 2 (mkKey <$> get16) (len - 2)
        pure $ SVCParamValue $ mkMandatory $ Set.fromList $ k : ks
      where
        mkKey :: Word16 -> SVCParamKey
        mkKey = coerce
        mkMandatory :: Set SVCParamKey -> SPV_mandatory
        mkMandatory = coerce

-- | [alpn](https://datatracker.ietf.org/doc/html/rfc9460#section-7.1)
-- The @alpn@ and @no-default-alpn@ @SVCB@ parameters together indicate the set
-- of Application-Layer Protocol Negotiation (@ALPN@) protocol identifiers
-- [ALPN](https://datatracker.ietf.org/doc/html/rfc7301) and associated
-- transport protocols supported by this service endpoint (the "SVCB ALPN
-- set").
newtype SPV_alpn = SPV_ALPN (NonEmpty ShortByteString)
    deriving (Typeable, Eq, Show)

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
    spvKey     = ALPN
    encodeSPV (SPV_ALPN vs) = do
        passLen $ forM_ vs $ putShortByteStringLen8 . coerce
    decodeSPV len = do
        pos0 <- getPosition
        a <- getShortByteStringLen8
        pos1 <- getPosition
        let used = pos1 - pos0
        as <- getVarWidthSequence getShortByteStringLen8 (len - used)
        pure $ SVCParamValue . SPV_ALPN $ a :| as

-- | [no-default-alpn](https://datatracker.ietf.org/doc/html/rfc9460#section-7.1)
-- The @alpn@ and @no-default-alpn@ @SVCB@ parameters together indicate the set
-- of Application-Layer Protocol Negotiation (@ALPN@) protocol identifiers
-- [ALPN](https://datatracker.ietf.org/doc/html/rfc7301) and associated
-- transport protocols supported by this service endpoint (the "SVCB ALPN
-- set").
data SPV_ndalpn = SPV_NDALPN
    deriving (Typeable, Eq, Ord, Show)

instance Presentable SPV_ndalpn where
    present _ = present NODEFAULTALPN

instance KnownSVCParamValue SPV_ndalpn where
    spvKey = NODEFAULTALPN
    encodeSPV _ = put16 0
    decodeSPV _ = pure $ SVCParamValue SPV_NDALPN

-- | [port](https://datatracker.ietf.org/doc/html/rfc9460#section-7.2)
-- This @SVCB@ parameter defines the TCP or UDP port that should be used to
-- reach this alternative endpoint.
newtype SPV_port = SPV_PORT Word16
    deriving newtype (Typeable, Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

instance Presentable SPV_port where
    present (SPV_PORT port) =
        present PORT
        . presentCharSep '=' port

instance KnownSVCParamValue SPV_port where
    spvKey = PORT
    encodeSPV = putSizedBuilder . mappend (mbWord16 2) . mbWord16 . coerce
    decodeSPV _ = SVCParamValue . SPV_PORT <$> get16

-- | [ipv4hint](https://datatracker.ietf.org/doc/html/rfc9460#section-7.3)
-- This @SVCB@ parameter holds speculative IPv4 address hints for a given SVCB
-- target, that may speed up initial connections before more authoritative data
-- becomes available.
newtype SPV_ipv4hint = SPV_IPV4HINT (NonEmpty IPv4)
    deriving (Typeable, Eq)

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
    spvKey = IPV4HINT
    encodeSPV (SPV_IPV4HINT ips) = passLen $ mapM_ putIPv4 ips
    decodeSPV n = do
        ip  <- getIPv4
        ips <- getFixedWidthSequence 4 getIPv4 (n - 4)
        return $ SVCParamValue $ SPV_IPV4HINT (ip :| ips)

-- | [ipv6hint](https://datatracker.ietf.org/doc/html/rfc9460#section-7.3)
-- This @SVCB@ parameter holds speculative IPv6 address hints for a given SVCB
-- target, that may speed up initial connections before more authoritative data
-- becomes available.
newtype SPV_ipv6hint = SPV_IPV6HINT (NonEmpty IPv6)
    deriving (Eq, Typeable)

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
    spvKey = IPV6HINT
    encodeSPV (SPV_IPV6HINT ips) = passLen $ mapM_ putIPv6 ips
    decodeSPV n = do
        ip  <- getIPv6
        ips <- getFixedWidthSequence 16 getIPv6 (n - 16)
        return $ SVCParamValue $ SPV_IPV6HINT (ip :| ips)

-- | [ech](https://datatracker.ietf.org/doc/html/rfc9460#section-14.3.2)
-- This @SVCB@ parameter supports Encrypted Client Hello, as described in the
-- [ECH Draft](https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni-17#section-4).
--
newtype SPV_ech = SPV_ECH Bytes64
    deriving (Typeable, Eq, Show)

instance Ord SPV_ech where
    compare = dnsTextCmp

instance Presentable SPV_ech where
    present (SPV_ECH c) = present ECH . presentCharSep '=' c

instance KnownSVCParamValue SPV_ech where
    spvKey = ECH
    encodeSPV (SPV_ECH c) = putShortByteStringLen16 $ coerce c
    decodeSPV 0 = failSGet "Invalid empty 'ech' ParamKey value"
    decodeSPV n
        | n < 4 = failSGet "'ech' ParamKey value too short"
        | otherwise = SVCParamValue . SPV_ECH . coerce <$> getShortNByteString n

-- | [dohpath](https://datatracker.ietf.org/doc/html/rfc9461#name-new-svcparamkey-dohpath)
-- This @SVCB@ parameter may be seen in responses to resolver discovery via
-- queries for "_dns.resolver.arpa IN SVCB ?", or via explicit queries to a
-- particular operator's resolver.
--
newtype SPV_dohpath = SPV_DOHPATH T.Text
    deriving (Eq, Typeable, Show)

instance Ord SPV_dohpath where
    compare (SPV_DOHPATH a) (SPV_DOHPATH b) =
        comparing T.lengthWord8 a b
        <> compare a b

instance Presentable SPV_dohpath where
    present (SPV_DOHPATH uri) =
        present DOHPATH . presentCharSep @DnsUtf8Text '=' (coerce uri)

instance KnownSVCParamValue SPV_dohpath where
    spvKey = DOHPATH
    encodeSPV (SPV_DOHPATH uri) = putUtf8TextLen16 uri
    decodeSPV = SVCParamValue . SPV_DOHPATH <.> getUtf8Text
