-- |
-- Module      : Net.DNSBase.Resolver.Internal.Types
-- Description : Internal types for resolver configuration and handles
-- Copyright   : (c) IIJ Innovation Institute Inc., 2009
--               (c) Viktor Dukhovni, 2020-2026
-- License     : BSD-3-Clause
-- Maintainer  : ietf-dane@dukhovni.org
-- Stability   : unstable
{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.Resolver.Internal.Types
     (
     -- * Static resolver configuration
       ResolverConf(..)
     , NameserverConf(..)
     , NameserverSpec(..)
     , Nameserver(..)
     -- ** Derived resolver objects
     , ResolvSeed(..)
     , Resolver(..)
     , withResolver
     -- ** Resolver control structures
     , RDataMap
     , OptionMap
     , EdnsControls
     , QueryControls(
         QctlFlags
       , EdnsEnabled
       , EdnsDisabled
       , EdnsVersion
       , EdnsUdpSize
       , EdnsOptionCtl
       )
     -- * Resolver Monad
     , DNSIO
     , runDNSIO
     , liftDNS
     , makeQueryFlags
     ) where

import qualified Crypto.Random as C
import qualified Data.IORef as I
import Data.List (intercalate)
import Network.Socket (AddrInfo(..), PortNumber)

import Net.DNSBase.Decode.Internal.Option
import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.Internal.EDNS
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Flags
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.Util

-- | An opt-in monad for chaining multiple DNS operations with
-- short-circuit error handling.  The primary public API uses plain
-- @'IO' ('Either' 'DNSError' a)@; 'DNSIO' is a thin wrapper around
-- @'ExceptT' 'DNSError' 'IO'@ for users who prefer transformer-style
-- composition.  Convert between the two forms with 'runDNSIO' and
-- 'liftDNS'.
type DNSIO = ExceptT DNSError IO

-- | Run a 'DNSIO' computation and return its @'Either' 'DNSError' a@
-- result in plain 'IO'.
runDNSIO :: DNSIO a -> IO (Either DNSError a)
runDNSIO = runExceptT

-- | Lift a plain @'IO' ('Either' 'DNSError' a)@ action into 'DNSIO',
-- for combining with other 'DNSIO' steps.
liftDNS :: IO (Either DNSError a) -> DNSIO a
liftDNS = ExceptT

-- | User-supplied resolver configuration.  Carries the caller's
-- choices: where nameservers come from, the per-attempt timeout
-- and retry budget, default 'QueryControls', and any
-- user-registered RR-type / EDNS option codecs.  Built-in defaults
-- are not stored here — they are merged into the effective
-- configuration only when 'Net.DNSBase.Resolver.makeResolvSeed' produces a 'ResolvSeed'.
data ResolverConf = ResolverConf
    { rcSource    :: NameserverConf -- ^ Nameserver source: a resolver-conf file path or an explicit list.
    , rcTimeout   :: Int            -- ^ Per-attempt timeout in microseconds.
    , rcRetries   :: Int            -- ^ Maximum number of attempts, including the first.
    , rcQryCtls   :: QueryControls  -- ^ Default query-flag and EDNS controls.
    , rcRDataMap  :: RDataMap       -- ^ User-registered RR-type codecs, indexed by 'Net.DNSBase.RRTYPE.RRTYPE' code.
    , rcOptionMap :: OptionMap      -- ^ User-registered EDNS option codecs, indexed by 'Net.DNSBase.EDNS.OptNum.OptNum'.
    }

-- | Configuration file name, or explicit list of addresses/hostnames.
data NameserverConf = SourceFile FilePath
                    | HostList (NonEmpty NameserverSpec)

-- | Nameserver address string or hostname, with optional port.
--
data NameserverSpec = NameserverSpec
    { nameserverName :: String
    , nameserverPort :: Maybe PortNumber
    }

----------------------------------------------------------------

data Nameserver = Nameserver
    { nsName :: Maybe String    -- ^ Hostname when specified
    , nsAddr :: AddrInfo        -- ^ Corresponding address
    }

instance Show Nameserver where
    showsPrec _ (Nameserver {..}) =
        maybe id showString nsName
        . showChar '['
        . shows (addrAddress nsAddr)
        . showChar ']'

-- | Resolved, immutable resolver state built by 'Net.DNSBase.Resolver.makeResolvSeed'
-- from a 'ResolverConf'.  Combines the user's choices with the
-- library's built-in defaults: resolved nameserver addresses,
-- and the effective RR-type and EDNS-option codec maps with
-- user-registered code points overriding the library defaults
-- (except at a small set of protected code points, where
-- attempted user overrides are silently ignored).
--
-- A 'ResolvSeed' is safe to share across threads; each query-issuing
-- thread should call 'withResolver' on the same seed to obtain its
-- own per-thread 'Resolver' handle.
data ResolvSeed = ResolvSeed
    { seedConfig    :: ResolverConf       -- ^ Caller's original 'ResolverConf'.
    , seedRDataMap  :: RDataMap           -- ^ Effective RR-type codec map.
    , seedOptionMap :: OptionMap          -- ^ Effective EDNS option codec map.
    , seedServers   :: NonEmpty Nameserver -- ^ Resolved nameserver endpoints.
    }

-- | Internal DNS Resolver handle, obtained via 'withResolver'.
-- Must not be used concurrently in multiple threads.
--
data Resolver = Resolver
    { resolvSeed :: ResolvSeed -- ^ Used to construct the resolver
    , resolvRng  :: IO Word64  -- ^ Resolver's RNG
    }

-- | Provide a 'Resolver' to the supplied action.  Concurrent use of a
-- single 'Resolver' is /not/ supported: the handle carries internal
-- mutable state and the library makes no soundness guarantees if it
-- is shared across threads.  Programs that issue queries from
-- multiple threads must call 'withResolver' once per worker thread
-- (typically inside @forkIO@) to obtain a separate handle.  The
-- 'ResolvSeed' itself is immutable and is the right object to share
-- across threads.
--
-- The action runs in plain 'IO'; DNS-protocol errors from individual
-- lookups appear in the @'Either' 'DNSError' a@ return shape of each
-- lookup function inside the action.  This function does not itself
-- produce or propagate 'DNSError's.
withResolver :: ResolvSeed -> (Resolver -> IO a) -> IO a
withResolver resolvSeed f = do
    resolvRng <- getRandom <$> (C.drgNew >>= I.newIORef)
    f Resolver{..}
  where
    getRandom :: I.IORef C.ChaChaDRG -> IO Word64
    getRandom ref = do
        gen <- I.readIORef ref
        let (bs, gen') = C.randomBytesGenerate 8 gen
            !w = word64be bs
        w <$ I.writeIORef ref gen'

----------------------------------------------------------------

-- * Query control monoids

-- | Query controls consisting of an endomorphism over 'FlagOps' to modify
-- DNS flag bits, and an 'EdnsControls' structure to configure EDNS
-- behavior.
--
-- Constitutes a 'Monoid' with left-biased mappend operation
data QueryControls = QueryControls (FlagOps -> FlagOps) EdnsControls

instance Show QueryControls where
    showsPrec p (QueryControls fctl ectl) = showsP p $
        showString "QueryControls "
        . shows' (fctl emptyFlagOps) . showChar ' '
        . shows' ectl

instance Semigroup QueryControls where
    (QueryControls fl1 edns1) <> (QueryControls fl2 edns2) =
        QueryControls (fl1 . fl2) (edns1 <> edns2)

instance Monoid QueryControls where
    mempty = QueryControls id mempty

-- | Apply the requested DNS flag operation, setting or clearing the requested
-- flag bits, or restoring defaults.
pattern QctlFlags :: (FlagOps -> FlagOps) -- ^ Desired 'FlagOps' modifier
                  -> QueryControls
pattern QctlFlags fl <- QueryControls fl _ where
    QctlFlags fl = QueryControls fl mempty
{-# COMPLETE QctlFlags #-}

-- | Return the results of applying the flag query controls to the default
-- query flags, setting or clearing the requested flag bits.
makeQueryFlags :: QueryControls -> DNSFlags
makeQueryFlags (QctlFlags op) = applyFlagOps (op emptyFlagOps) defaultQueryFlags

-- | EDNS query controls.  When EDNS is disabled via @ednsEnabled FlagClear@,
-- all the other EDNS-related overrides have no effect. Semigroup append is
-- left-biased
data EdnsControls = EdnsControls
    (Maybe Bool)             -- ^ Enabled
    (Maybe Word8)            -- ^ Version
    (Maybe Word16)           -- ^ UDP Size
    (OptionCtl -> OptionCtl) -- ^ EDNS option list tweaks

instance Semigroup EdnsControls where
    (EdnsControls en1 vn1 sz1 od1) <> (EdnsControls en2 vn2 sz2 od2) =
        EdnsControls (en1 <|> en2) (vn1 <|> vn2) (sz1 <|> sz2) (od1 . od2)

instance Monoid EdnsControls where
    mempty = EdnsControls Nothing Nothing Nothing id

instance Show EdnsControls where
    show (EdnsControls en vn sz od) =
        _showOpts
            [ _showWord "edns.enabled" en
            , _showWord "edns.version" vn
            , _showWord "edns.udpsize" sz
            , _showOdOp "edns.options" $ show
                                       $ od emptyOptionCtl ]
      where
        _showOpts :: [String] -> String
        _showOpts os = intercalate "," $ filter (not . null) os

        _showWord :: Show a => String -> Maybe a -> String
        _showWord nm w = maybe "" (\s -> nm ++ ":" ++ show s) w

        _showOdOp :: String -> String -> String
        _showOdOp nm os = case os of
            "" -> ""
            _  -> nm ++ ":" ++ os

-- | Enable EDNS for this query, overriding the resolver default
-- if it had EDNS disabled.  The OPT pseudo-RR is included in the
-- outgoing query.
pattern EdnsEnabled :: QueryControls
pattern EdnsEnabled <-
    QueryControls _ (EdnsControls (Just True) _ _ _) where
    EdnsEnabled = QueryControls id (EdnsControls (Just True) Nothing Nothing id)

-- | Disable EDNS for this query.  When EDNS is disabled, the OPT
-- pseudo-RR is omitted from the outgoing query and the other
-- EDNS-related tweaks ('EdnsVersion', 'EdnsUdpSize',
-- 'EdnsOptionCtl') have no effect on the wire.
pattern EdnsDisabled :: QueryControls
pattern EdnsDisabled <-
    QueryControls _ (EdnsControls (Just False) _ _ _) where
    EdnsDisabled = QueryControls id (EdnsControls (Just False) Nothing Nothing id)

-- | Override the EDNS version advertised in the OPT pseudo-RR
-- for this query.  Only version @0@ is specified, and versions
-- other than @0@ are unlikely to be interoperable at present.
pattern EdnsVersion :: Word8 -- ^ Desired version
                    -> QueryControls
pattern EdnsVersion vn <-
    QueryControls _ (EdnsControls _ (Just vn) _ _) where
    EdnsVersion vn = QueryControls id (EdnsControls Nothing (Just vn) Nothing id)

-- | Override the maximum UDP payload size the client advertises
-- to the server for this query.  The value is clamped to the
-- 'minUdpSize' / 'maxUdpSize' range.
pattern EdnsUdpSize :: Word16 -- ^ Desired size
                    -> QueryControls
pattern EdnsUdpSize sz <-
    QueryControls _ (EdnsControls _ _ (Just sz) _) where
    EdnsUdpSize sz = QueryControls id (EdnsControls Nothing Nothing (Just capped) id)
      where
        !capped = max minUdpSize . min maxUdpSize $ sz

-- | Carry a per-call modification of the OPT pseudo-RR's EDNS
-- option list as an endomorphism @'OptionCtl' -> 'OptionCtl'@.
-- The endomorphism is applied to the resolver's ambient option
-- list at query-build time, so callers express deltas — clear
-- everything, add an option, replace an option — rather than full
-- replacements.
--
-- 'optCtlAdd' and 'optCtlSet' are the standard ways to build the
-- endomorphism.  For example, to opt out of geolocation-tailored
-- answers for a single query by signalling \"do not use my
-- subnet\" via ECS with a zero-length source prefix
-- ([RFC 7871 section 7.1.2](https://datatracker.ietf.org/doc/html/rfc7871#section-7.1.2)):
--
-- > let noEcs = EdnsOptionCtl
-- >           $ optCtlAdd [ EdnsOption
-- >                       $ O_ECS 0 0 (IPv4 (toIPv4 [0,0,0,0])) ]
-- >  in lookupAnswers rslv noEcs IN A $$(dnLit8 "example.org")
--
-- 'optCtlAdd' replaces the resolver's existing ECS option (if
-- any) with this one because they share an @OPTCODE@; other
-- options the resolver had configured pass through untouched.
-- 'optCtlSet' would instead clear the entire option list and use
-- only the supplied options.
pattern EdnsOptionCtl :: (OptionCtl -> OptionCtl)
                         -- ^ Selected modifier: optCtlAdd, ...
                      -> QueryControls
pattern EdnsOptionCtl omod <-
    QueryControls _ (EdnsControls _ _ _ omod) where
    EdnsOptionCtl omod = QueryControls id (EdnsControls Nothing Nothing Nothing omod)
{-# COMPLETE EdnsOptionCtl #-}
