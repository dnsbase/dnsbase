{-|
Module      : Net.DNSBase.Resolver
Description : Stub resolver configuration and per-thread handles
Copyright   : (c) IIJ Innovation Institute Inc., 2009
              (c) Viktor Dukhovni, 2020-2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The resolver is built in three stages:

1. 'ResolverConf' carries the caller's choices: nameserver
   source, per-attempt timeout, retry budget, default
   'QueryControls', and any user-registered RR-type or EDNS
   option codecs.  Build one by adjusting fields of
   'defaultResolvConf'.

2. 'makeResolvSeed' turns a 'ResolverConf' into a 'ResolvSeed':
   nameserver hostnames are resolved to addresses, and the
   user's codec registrations are merged with the library's
   built-in defaults.  The seed is immutable and safe to share
   across threads.

3. 'withResolver' produces a per-thread 'Resolver' handle from
   a shared seed.  A 'Resolver' carries thread-local mutable
   state (a CSPRNG for query IDs) and /must not/ be shared
   between threads — programs that issue queries concurrently
   should call 'withResolver' once per worker thread.

A minimal example:

> main :: IO ()
> main = do
>     seed <- makeResolvSeed defaultResolvConf >>= either throwIO pure
>     withResolver seed \ r ->
>         lookupA r $$(dnLit8 "example.com") >>= \ case
>             Left  e -> throwIO e
>             Right a -> print a

The codec set baked into the seed can be extended at
conf-build time via 'registerRRtype' / 'registerEdnsOption'
(new RR-type or EDNS-option codecs) and the four
'extendRRwithType' / 'extendRRwithValue' /
'extendEdnsOptionWithType' / 'extendEdnsOptionWithValue'
combinators (extensions onto codecs that admit them).  See
"Net.DNSBase.Extensible" for worked examples.
-}
{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.Resolver
  ( -- * Resolver configuration
    ResolverConf
  , defaultResolvConf
  , setResolverConfTimeout
  , setResolverConfRetries
  , setResolverConfQueryControls
  , setResolverConfSource
  , NameserverConf(..)
  , NameserverSpec(..)
  -- * Resolver seed
  , ResolvSeed
  , makeResolvSeed
  -- * Resolver instance
  , Resolver(resolvSeed, resolvRng)
  , withResolver
  -- * Look up 'RRTYPE' by name.
  , RRtypeNames
  , confTypeNames
  , rrtypeLookup
  -- * Controls.
  -- ** Query controls.
  , QueryControls(..)
  , EdnsControls
  -- ** Extending the codec set.
  --
  -- $extending
  , TypeExtensible(..)
  , KnownRData(..)
  , registerRRtype
  , extendRRwithType
  , extendRRwithValue
  , KnownEdnsOption(..)
  , registerEdnsOption
  , extendEdnsOptionWithType
  , extendEdnsOptionWithValue
  -- * Chained-composition opt-in
  --
  -- $dnsio
  , DNSIO
  , runDNSIO
  , liftDNS
  ) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Builder.Extra as B
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Short as SB
import qualified Data.IntMap.Strict as IM
import qualified Data.Map.Strict as M
import qualified Data.Type.Equality as R
import qualified Type.Reflection as R
import Data.Char (chr)
import Data.String (fromString)
import Data.Void (Void)
import Network.Socket ( AddrInfo(..), AddrInfoFlag(..), HostName, PortNumber )
import Network.Socket ( ServiceName, SocketType(Datagram) )
import Network.Socket ( defaultHints, getAddrInfo )
import Numeric (readDec)
import Numeric.Natural (Natural)
import GHC.IO.Exception (IOErrorType(..))
import System.IO.Error (ioeSetErrorString, mkIOError, tryIOError)

import Net.DNSBase.Decode.Internal.Option
import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.EDNS.Internal.OptNum
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.Util
import Net.DNSBase.Nat16
import Net.DNSBase.Resolver.Internal.Parser
import Net.DNSBase.Resolver.Internal.Types

import Net.DNSBase.EDNS.Option.ECS
import Net.DNSBase.EDNS.Option.EDE
import Net.DNSBase.EDNS.Option.NSID
import Net.DNSBase.EDNS.Option.Secalgs
import Net.DNSBase.Extensible (TypeExtensible(..), ValueExtensible(..))

-- Built-in RData type modules
import Net.DNSBase.RData.A
import Net.DNSBase.RData.CAA
import Net.DNSBase.RData.CSYNC
import Net.DNSBase.RData.Dnssec
-- Re-exported by Dnssec
-- import Net.DNSBase.RData.NSEC
import Net.DNSBase.RData.Obsolete
import Net.DNSBase.RData.SOA
import Net.DNSBase.RData.SRV
import Net.DNSBase.RData.SVCB
import Net.DNSBase.RData.TLSA
import Net.DNSBase.RData.TXT
-- Re-exported by Obsolete
-- import Net.DNSBase.RData.WKS
import Net.DNSBase.RData.XNAME

----

-- $dnsio
-- The primary API (e.g. 'makeResolvSeed', 'Net.DNSBase.Lookup.lookupAnswers') returns
-- @'IO' ('Either' 'DNSError' a)@: each call's error half is explicit
-- at the type level and the user's surrounding code stays in plain
-- 'IO'.  For programs that prefer transformer-style composition of
-- many DNS calls with short-circuit error handling, 'DNSIO' is a thin
-- alias for @'ExceptT' 'DNSError' 'IO'@; 'runDNSIO' and 'liftDNS'
-- convert between the two forms.

-- Set Resolver timeout
setResolverConfTimeout :: Int -> ResolverConf -> ResolverConf
setResolverConfTimeout t rc = rc {rcTimeout = t}

-- Set Resolver retries
setResolverConfRetries :: Int -> ResolverConf -> ResolverConf
setResolverConfRetries n rc = rc {rcRetries = n}

-- Set Resolver configuration source
setResolverConfSource :: NameserverConf -> ResolverConf -> ResolverConf
setResolverConfSource s rc = rc {rcSource = s}

-- Set Resolver query controls
setResolverConfQueryControls :: QueryControls -> ResolverConf -> ResolverConf
setResolverConfQueryControls q rc = rc {rcQryCtls = q}

-- $extending
-- The resolver knows about a set of RR-type and EDNS-option
-- codecs at conf-build time.  'registerRRtype' and
-- 'registerEdnsOption' install a fresh codec entry at the
-- type's default extension value; the four
-- 'extendRRwithType' / 'extendRRwithValue' /
-- 'extendEdnsOptionWithType' / 'extendEdnsOptionWithValue'
-- combinators fold typed or value-driven extensions onto an
-- already-extensible codec's existing entry.  See
-- "Net.DNSBase.Extensible" for worked examples and the design
-- behind the two extension flavours.
--
-- User registrations take precedence over the library's
-- built-in codec set, except at a small number of /protected/
-- code points (e.g. the SVCB @mandatory@ key), where attempted
-- user additions are silently ignored.

-- | Register a decoder for an RR-type.
-- If the RR's data type is itself extensible, you can
-- use 'extendRRwithType' or 'extendRRwithValue' to
-- apply additional extensions on top.
--
-- The registration takes precedence over the library's built-in
-- codec at the same RR-type code, except at protected code
-- points (e.g. RR-type 0 and 65535, or the OPT pseudo-RR), where
-- the registration is silently ignored.
registerRRtype :: forall a -> KnownRData a
               => ResolverConf -> ResolverConf
registerRRtype a rc =
    rc { rcRDataMap = IM.insert key entry (rcRDataMap rc) }
  where
    key   = fromIntegral @Word16 . coerce $ rdType a
    entry = RDataCodec (Proxy @a) (rdataExtensionVal a)

-- | Extend the registered codec of a type-extensible RR type @t@
-- with an additional typed extension @b@.  If @t@ is not yet
-- known it is automatically registered, in either case 'extendByType'
-- is then applied to the existing decoder state to fold in @b@.
--
-- This is how one adds an extra SvcParam-key decoder for SVCB
-- and/or HTTPS records.
--
-- > conf
-- >     & extendRRwithType T_svcb  MyParamType
-- >     & extendRRwithType T_https MyParamType
--
extendRRwithType :: forall t ->
                    ( KnownRData t
                    , TypeExtensible t (RDataExtensionVal t)
                    )
                 => forall b -> TypeExtensionArg t b
                 => ResolverConf -> ResolverConf
extendRRwithType t b rc =
    rc { rcRDataMap = IM.insert key entry (rcRDataMap rc) }
  where
    key      = fromIntegral @Word16 . coerce $ rdType t
    baseline = case IM.lookup key (rcRDataMap rc) of
        Just (RDataCodec (_ :: Proxy a) opts)
            | Just R.Refl <- R.testEquality (R.typeRep @t) (R.typeRep @a)
            -> opts
        _   -> rdataExtensionVal t
    entry    = RDataCodec (Proxy @t) (extendByType t b baseline)

-- | Register an EDNS option decoder.
-- If the EDNS option\'s data type is itself extensible, you can
-- use 'extendEdnsOptionWithType' or 'extendEdnsOptionWithValue' to
-- apply additional extensions on top.
--
-- The registration takes precedence over the library's built-in
-- decoder at the same option code (if any) after the merge step
-- in 'makeResolvSeed'.
registerEdnsOption :: forall a -> KnownEdnsOption a
                   => ResolverConf -> ResolverConf
registerEdnsOption a rc =
    rc { rcOptionMap = IM.insert key entry (rcOptionMap rc) }
  where
    key   = fromIntegral @Word16 . coerce $ optNum a
    entry = OptionCodec (Proxy @a) (optionExtensionVal a)

-- | Extend the registered decoder for a type-extensible EDNS option
-- type @t@ with an additional typed extension @b@.  If @t@ is not
-- yet present in the resolver configuration, it is first registered,
-- in either case 'extendByType' is then applied fold in @b@.
--
-- This is the EDNS-option-side parallel to 'extendRRwithType'.
extendEdnsOptionWithType :: forall t ->
                            ( KnownEdnsOption t
                            , TypeExtensible t (OptionExtensionVal t)
                            )
                         => forall b -> TypeExtensionArg t b
                         => ResolverConf -> ResolverConf
extendEdnsOptionWithType t b rc =
    rc { rcOptionMap = IM.insert key entry (rcOptionMap rc) }
  where
    key      = fromIntegral @Word16 . coerce $ optNum t
    baseline = case IM.lookup key (rcOptionMap rc) of
        Just (OptionCodec (_ :: Proxy a) opts)
            | Just R.Refl <- R.testEquality (R.typeRep @t) (R.typeRep @a)
            -> opts
        _   -> optionExtensionVal t
    entry    = OptionCodec (Proxy @t) (extendByType t b baseline)

-- | Extend the registered codec for RR type @t@ with a
-- caller-supplied value @v@, whose type satisfies @t@'s
-- 'ValueExtensionArg' constraint.  Parallel to
-- 'extendRRwithType', but for instances whose extension table
-- is keyed by runtime data rather than user-supplied types.
extendRRwithValue :: forall t ->
                     ( KnownRData t
                     , ValueExtensible t (RDataExtensionVal t)
                     )
                  => forall b. ValueExtensionArg t b
                  => b -> ResolverConf -> ResolverConf
extendRRwithValue t v rc =
    rc { rcRDataMap = IM.insert key entry (rcRDataMap rc) }
  where
    key      = fromIntegral @Word16 . coerce $ rdType t
    baseline = case IM.lookup key (rcRDataMap rc) of
        Just (RDataCodec (_ :: Proxy a) opts)
            | Just R.Refl <- R.testEquality (R.typeRep @t) (R.typeRep @a)
            -> opts
        _   -> rdataExtensionVal t
    entry    = RDataCodec (Proxy @t) (extendByValue t v baseline)

-- | Extend the registered codec for EDNS option type @t@ with
-- a caller-supplied value @v@, whose type satisfies @t@'s
-- 'ValueExtensionArg' constraint.  The EDNS-option-side
-- parallel to 'extendRRwithValue'.  This is the canonical way
-- to add an EDE info-code → friendly-name mapping:
--
-- > conf
-- >     & extendEdnsOptionWithValue O_ede (33, "Frobnicated")
-- >     & extendEdnsOptionWithValue O_ede (34, "Bogosity")
extendEdnsOptionWithValue :: forall t ->
                             ( KnownEdnsOption t
                             , ValueExtensible t (OptionExtensionVal t)
                             )
                          => forall b. ValueExtensionArg t b
                          => b -> ResolverConf -> ResolverConf
extendEdnsOptionWithValue t v rc =
    rc { rcOptionMap = IM.insert key entry (rcOptionMap rc) }
  where
    key      = fromIntegral @Word16 . coerce $ optNum t
    baseline = case IM.lookup key (rcOptionMap rc) of
        Just (OptionCodec (_ :: Proxy a) opts)
            | Just R.Refl <- R.testEquality (R.typeRep @t) (R.typeRep @a)
            -> opts
        _   -> optionExtensionVal t
    entry    = OptionCodec (Proxy @t) (extendByValue t v baseline)


-- | Build a 'ResolvSeed' from a 'ResolverConf'.  The seed is
-- immutable and safely shared across threads; each thread then
-- calls 'withResolver' to obtain its own 'Resolver'.
--
-- The configured nameservers are resolved to socket addresses,
-- and the user's codec registrations (from 'registerRRtype',
-- 'extendRRwithType' and 'registerEdnsOption') are combined with the
-- library's built-in codec set.  At each RR-type or EDNS option
-- code point, the user-registered codec takes precedence over the
-- library default — except at a small set of /protected/ code
-- points (e.g. the SVCB @mandatory@ key), where any attempted
-- user override is silently ignored.
--
-- Returns @'Left' err@ if the configured nameservers cannot be
-- resolved or the configuration file cannot be parsed.
--
-- Example:
--
-- >>> seed <- makeResolvSeed defaultResolvConf >>= either throwIO pure
--
makeResolvSeed :: ResolverConf -> IO (Either DNSError ResolvSeed)
makeResolvSeed conf = runDNSIO do
    seedServers <- findAddresses
    let !seedRDataMap  = reservedCodecs
                        `IM.union` (rcRDataMap conf `IM.union` defaultCodecs)
        !seedOptionMap = rcOptionMap conf `IM.union` baseOptions
        seedConfig     = conf
    pure ResolvSeed{..}
  where
    findAddresses :: DNSIO (NonEmpty Nameserver)
    findAddresses = case rcSource conf of
        HostList rs     -> join <$> mapM getNameserverAddresses rs
        SourceFile file -> getDefaultNameservers file >>= mkAddrs

    getNameserverAddresses (NameserverSpec h mp) = makeAddrInfo (Just h) mp

    -- When /etc/resolv.conf contains no addresses, default to the loopback address,
    -- by passing 'Nothing' for the server name.
    mkAddrs []     = makeAddrInfo Nothing Nothing
    mkAddrs (l:ls) = join <$> mapM getNameserverAddresses (l :| ls)


-- | Default resolver configuration, with nameserver list from
-- @\/etc\/resolv.conf@ and no user-registered codec extensions.
defaultResolvConf :: ResolverConf
defaultResolvConf = ResolverConf
    { rcSource    = SourceFile "/etc/resolv.conf"
    , rcTimeout   = 3_000_000  -- 3 seconds
    , rcRetries   = 3
    , rcQryCtls   = mempty
    , rcRDataMap  = IM.empty
    , rcOptionMap = IM.empty
    }

-- | Determines whether a HostName is a valid IPv4 or IPv6 address
--
-- Also false if input is an IPv4 or IPv6 address with trailing characters,
-- or in the (impossible) case of multiple valid parses
isAddr :: HostName -> Bool
isAddr addr =
    case reads @IP addr of
        [(_,r)] -> null r
        _       -> False

makeAddrInfo :: Maybe HostName -> Maybe PortNumber -> DNSIO (NonEmpty Nameserver)
makeAddrInfo maddr mport = do
    let flags | addrLiteral = AI_NUMERICHOST : defaultFlags
              | otherwise   = defaultFlags
        hints = defaultHints {addrFlags = flags, addrSocketType = Datagram}
        serv = maybe "53" show mport

    -- getAddrInfo should never return an empty list (it raises an IO exception instead),
    -- but just in case, handle empty results.
    withExceptT BadNameserver (getAddrInfo' hints maddr serv) >>= \ case
        a : as -> pure $ Nameserver addrName <$> a :| as
        _      -> let host = fromMaybe defaultHostName maddr
                      ioe = mkIOError NoSuchThing host Nothing Nothing
                   in throwE $ BadNameserver $ ioeSetErrorString ioe "Host unknown"
  where
    defaultFlags = [AI_NUMERICSERV, AI_ADDRCONFIG]
    defaultHostName = "localhost"
    addrLiteral = maybe False isAddr maddr
    addrName | addrLiteral = Nothing
             | otherwise   = maddr <|> Just defaultHostName

getAddrInfo' :: AddrInfo -> Maybe HostName -> ServiceName -> ExceptT IOError IO [AddrInfo]
getAddrInfo' h a s = ExceptT $ tryIOError (getAddrInfo (Just h) a (Just s))

---------- RRTYPE lookups

-- | Mapping from @RRTYPE@ name to 'RRTYPE' code.
newtype RRtypeNames = RRNames_ (M.Map SB.ShortByteString RRTYPE)

-- | Attempt to find an RRTYPE' by name.  The lookup map can be constructed
-- via 'confTypeNames', and should be reused for multiple lookups when
-- possible.
--
-- - The input name is not case-senstive.
-- - Names of the form @TYPE@/num/ (with /num/ the type number) are supported,
--   and return the corresponding 'RRTYPE'.
rrtypeLookup :: B.ByteString
             -> RRtypeNames
             -> Maybe RRTYPE
rrtypeLookup ((,) <$> B.length <*> B.unpack -> (len, ws)) (coerce -> m)
    | t@(Just _) <- M.lookup name m
    = t
    | SB.isPrefixOf rrtypePrefix name
    , digits <- map (chr . fromIntegral) $ drop (SB.length rrtypePrefix) ws
    , [(w, "")] <- readDec @Natural digits
    , w <= fromIntegral @Word16 @Natural maxBound
    = Just $! RRTYPE $ fromIntegral w
    | otherwise
    = Nothing
  where
    name = foldShort len ws

-- | Construct a map of type names to 'RRTYPE' from a given
-- 'ResolvSeed' value.  This will include both the names of all
-- the registered known types and the names of all known RRtypes,
-- whether implemented or not.
--
-- The map is is not cached, compute it once and reuse for
-- repeated queries.
--
confTypeNames :: Maybe ResolvSeed -> RRtypeNames
confTypeNames cnf =
    coerce $ maybe M.empty cnfMap cnf <> M.fromList knownNames
  where
    cnfMap ResolvSeed {seedRDataMap = dm} =
        M.fromList $ map (uncurry mkPair) $ IM.toList dm
      where
        mkPair k (RDataCodec p _) =
            (proxyName p, RRTYPE $ fromIntegral k)
        proxyName :: forall a. KnownRData a
                  => Proxy a -> SB.ShortByteString
        proxyName _ = buildShort $ rdTypePres a mempty

    knownNames = [ (name, t)
                 | t <- [A .. rrtypeMax]
                 , let name = buildShort $ present t mempty
                 , not $ SB.isPrefixOf rrtypePrefix name ]

    buildShort = (foldShort <$> LB.length <*> LB.unpack) . buildLazy
    buildLazy = B.toLazyByteStringWith (B.untrimmedStrategy 16 32) mempty

foldShort :: Integral a => a -> [Word8] -> SB.ShortByteString
foldShort len = fst <$> SB.unfoldrN (fromIntegral len) low8
  where
    low8 [] = Nothing
    low8 (w:ws) | w - 0x41 < 26 = Just (w + 0x20, ws)
                | otherwise     = Just (w, ws)

rrtypePrefix :: SB.ShortByteString
rrtypePrefix = fromString "type"

-------------------------------
--- RData and Option codec maps

-- | Placeholder for reserved RRTYPEs.
type Reserved :: Nat -> Type
data Reserved n = Reserved_ Void deriving (Eq, Ord, Show)
instance (Nat16 n) => KnownRData (Reserved n) where
    rdType _ = RRTYPE $ natToWord16 n
    rdTypePres _ = present @String "Reserved" . present (natToWord16 n)
    rdEncode _   = failWith $ ReservedType $ RRTYPE $ natToWord16 n
    rdDecode _ _ = const do
        failSGet $ "Reserved RDATA type: " ++ show (natToWord16 n)
instance (Nat16 n) => Presentable (Reserved n) where
    present _ = undefined

-- Internal helper: build the 'RDataMap' entry for type @a@ from
-- its 'Net.DNSBase.RData.rdataExtensionVal'.
rdataMapEntry :: forall a -> KnownRData a => (Int, RDataCodec)
rdataMapEntry a =
    ( fromIntegral @Word16 . coerce $ rdType a
    , RDataCodec (Proxy @a) (rdataExtensionVal a)
    )

-- | Reserved RR-type slots: codes that the protocol forbids as
-- RDATA (RFC 6895 reserved code 0 and sentinel 65535), that the
-- library handles outside the RDATA codec map (OPT, code 41), or
-- that are meta-query types with no carriable RDATA (NXNAME,
-- TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY).
--
-- The merge step in 'Net.DNSBase.Resolver.makeResolvSeed' protects these entries from
-- user override: any user-supplied registration at one of these
-- codes is dropped in favour of the reserved entry.
reservedCodecs :: RDataMap
reservedCodecs = IM.fromList
    [ rdataMapEntry (Reserved 0)         -- 0 RFC6895
    , rdataMapEntry (Reserved 41)        -- 41 OPT (hardwired)
      ---- Special-use types
    , rdataMapEntry (Reserved 128)       -- NXNAME
    , rdataMapEntry (Reserved 249)       -- TKEY
    , rdataMapEntry (Reserved 250)       -- TSIG
    , rdataMapEntry (Reserved 251)       -- IXFR
    , rdataMapEntry (Reserved 252)       -- AXFR
      ---- Query-only types
    , rdataMapEntry (Reserved 253)       -- MAILB
    , rdataMapEntry (Reserved 254)       -- MAILA
    , rdataMapEntry (Reserved 255)       -- ANY
      ----
    , rdataMapEntry (Reserved 65535)     -- Reserved
    ]

-- | Built-in default codecs for the RR-types the library decodes
-- natively.  Disjoint from 'reservedCodecs'.
--
-- These act as fallbacks: a user-supplied registration for any
-- of these RR-types takes precedence over the built-in entry.
-- The merge step in 'Net.DNSBase.Resolver.makeResolvSeed' resolves overlaps in the
-- user's favour, so a caller can replace a built-in decoder with
-- their own without forking the library.
defaultCodecs :: RDataMap
defaultCodecs = IM.fromList
    [ rdataMapEntry T_a                  -- 1
    , rdataMapEntry T_ns                 -- 2
    , rdataMapEntry T_md                 -- 3
    , rdataMapEntry T_mf                 -- 4
    , rdataMapEntry T_cname              -- 5
    , rdataMapEntry T_soa                -- 6
    , rdataMapEntry T_mb                 -- 7
    , rdataMapEntry T_mg                 -- 8
    , rdataMapEntry T_mr                 -- 9
    , rdataMapEntry T_null               -- 10
    , rdataMapEntry T_wks                -- 11
    , rdataMapEntry T_ptr                -- 12
    , rdataMapEntry T_hinfo              -- 13
    , rdataMapEntry T_minfo              -- 14
    , rdataMapEntry T_mx                 -- 15
    , rdataMapEntry T_txt                -- 16
    , rdataMapEntry T_rp                 -- 17
    , rdataMapEntry T_afsdb              -- 18
    , rdataMapEntry T_x25                -- 19
    , rdataMapEntry T_isdn               -- 20
    , rdataMapEntry T_rt                 -- 21
    , rdataMapEntry T_nsap               -- 22
    , rdataMapEntry T_nsapptr            -- 23
    , rdataMapEntry T_sig                -- 24
    , rdataMapEntry T_key                -- 25
    , rdataMapEntry T_px                 -- 26
    , rdataMapEntry T_gpos               -- 27
    , rdataMapEntry T_aaaa               -- 28
                                         -- 29 LOC
    , rdataMapEntry T_nxt                -- 30
                                         -- 31 EID
                                         -- 32 NIMLOC
    , rdataMapEntry T_srv                -- 33
                                         -- 34 ATMA
    , rdataMapEntry T_naptr              -- 35
    , rdataMapEntry T_kx                 -- 36
                                         -- 37 CERT
    , rdataMapEntry T_a6                 -- 38
    , rdataMapEntry T_dname              -- 39
                                         -- 40 SINK
                                         -- 42 APL
    , rdataMapEntry T_ds                 -- 43
    , rdataMapEntry T_sshfp              -- 44
    , rdataMapEntry T_ipseckey           -- 45 IPSECKEY
    , rdataMapEntry T_rrsig              -- 46
    , rdataMapEntry T_nsec               -- 47
    , rdataMapEntry T_dnskey             -- 48
                                         -- 49 DHCID
    , rdataMapEntry T_nsec3              -- 50
    , rdataMapEntry T_nsec3param         -- 51
    , rdataMapEntry T_tlsa               -- 52
    , rdataMapEntry T_smimea             -- 53
                                         -- 54 Unassigned
                                         -- 55 HIP
                                         -- 56 NINFO
                                         -- 57 RKEY
                                         -- 58 TALINK
    , rdataMapEntry T_cds                -- 59
    , rdataMapEntry T_cdnskey            -- 60
    , rdataMapEntry T_openpgpkey         -- 61
    , rdataMapEntry T_csync              -- 62 CSYNC
    , rdataMapEntry T_zonemd             -- 63
    , rdataMapEntry T_svcb               -- 64
    , rdataMapEntry T_https              -- 65
    , rdataMapEntry T_dsync              -- 66
                                         -- 67 HHIT
                                         -- 68 BRID
                                         -- 99 SPF
    , rdataMapEntry T_nid                -- 104 NID
    , rdataMapEntry T_l32                -- 105 L32
    , rdataMapEntry T_l64                -- 106 L64
    , rdataMapEntry T_lp                 -- 107 LP
                                         -- 108 EUI48 [RFC7043]
                                         -- 109 EUI64 [RFC7043]
    , rdataMapEntry T_caa                -- 257
    , rdataMapEntry T_amtrelay           -- 260
                                         -- 261 RESINFO
                                         -- 262 WALLET
                                         -- 263 CLA
                                         -- 264 IPN
    ]

-- | Built-in EDNS option codecs.  User registrations from
-- 'Net.DNSBase.Resolver.registerEdnsOption' /
-- 'Net.DNSBase.Resolver.extendEdnsOptionWithType' take
-- precedence over entries here after the merge step in
-- 'Net.DNSBase.Resolver.makeResolvSeed'.
baseOptions :: OptionMap
baseOptions = IM.fromList
    [ optMapEntry O_nsid                                 -- 3 NSID
    , optMapEntry O_dau                                  -- 5 DAU
    , optMapEntry O_dhu                                  -- 6 DHU
    , optMapEntry O_n3u                                  -- 7 N3U
    , optMapEntry O_ecs                                  -- 8 ECS
    , optMapEntry O_ede                                  -- 15 EDE
    ]
  where
    optMapEntry :: forall a -> KnownEdnsOption a => (Int, OptionCodec)
    optMapEntry a =
        ( fromIntegral @Word16 . coerce $ optNum a
        , OptionCodec (Proxy @a) (optionExtensionVal a)
        )
