{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.Resolver
  ( -- * Resolver configuration
    Resolver
  , DNSIO
  , makeResolver
  , withResolver
  , ResolverConf
  , defaultResolvConf
  , pattern ResolverConfTimeout
  , pattern ResolverConfRetries
  , pattern ResolverConfSource
  , pattern ResolverConfQueryControls
  , pattern ResolverConfRDataMap
  , pattern ResolverConfOptionMap
  , makeResolvSeed
  , resolverCodecParamUpdate
  , ResolvSeed
  , NameserverConf(..)
  , NameserverSpec(..)
  -- * Look up 'RRTYPE' by name.
  , RRtypeNames
  , confTypeNames
  , rrtypeLookup
  -- * Controls.
  -- ** Query controls.
  , QueryControls(..)
  -- ** Decoder plugin maps for RData and EDNS options.
  , RDataMap
  , SomeCodec
  , getResolverConfRDataMap
  , setResolverConfRDataMap
  , OptionMap
  , rdataMapEntry
  , getResolverConfOptionMap
  , setResolverConfOptionMap
  ) where

import qualified Crypto.Random as C
import qualified Data.ByteString as B
import qualified Data.ByteString.Builder.Extra as B
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Short as SB
import qualified Data.IORef as I
import qualified Data.IntMap.Strict as IM
import qualified Data.Map.Strict as M
import qualified Data.Type.Equality as R
import qualified Type.Reflection as R
import Data.Char (chr)
import Data.IORef (IORef)
import Data.String (fromString)
import Network.Socket ( AddrInfo(..), AddrInfoFlag(..), HostName, PortNumber )
import Network.Socket ( ServiceName, SocketType(Datagram) )
import Network.Socket ( defaultHints, getAddrInfo )
import Numeric (readDec)
import Numeric.Natural (Natural)
import GHC.IO.Exception (IOErrorType(..))
import System.IO.Error (ioeSetErrorString, mkIOError, tryIOError)

import Net.DNSBase.Decode.Internal.Option
import Net.DNSBase.Decode.Map
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.Util
import Net.DNSBase.Resolver.Internal.Parser
import Net.DNSBase.Resolver.Internal.Types

-- Get or Set Resolver timeout
{-# COMPLETE ResolverConfTimeout #-}
pattern ResolverConfTimeout :: Int -> ResolverConf -> ResolverConf
pattern ResolverConfTimeout t rc <- rc@ResolverConf {rcTimeout = t} where
    ResolverConfTimeout t rc = rc {rcTimeout = t}

-- Get or Set Resolver retries
{-# COMPLETE ResolverConfRetries #-}
pattern ResolverConfRetries :: Int -> ResolverConf -> ResolverConf
pattern ResolverConfRetries n rc <- rc@ResolverConf {rcRetries = n} where
    ResolverConfRetries n rc = rc {rcRetries = n}

-- Get or Set Resolver configuration source
{-# COMPLETE ResolverConfSource #-}
pattern ResolverConfSource :: NameserverConf -> ResolverConf -> ResolverConf
pattern ResolverConfSource s rc <- rc@ResolverConf {rcSource = s} where
    ResolverConfSource s rc = rc {rcSource = s}

-- Get or Set Resolver query controls
{-# COMPLETE ResolverConfQueryControls #-}
pattern ResolverConfQueryControls :: QueryControls -> ResolverConf -> ResolverConf
pattern ResolverConfQueryControls q rc <- rc@ResolverConf {rcQryCtls = q} where
    ResolverConfQueryControls q rc = rc {rcQryCtls = q}

-- | Get the resolvers effective RData decoder map combining the built-in and
-- user-specified maps.
{-# COMPLETE ResolverConfRDataMap #-}
pattern ResolverConfRDataMap :: RDataMap -> ResolverConf
pattern ResolverConfRDataMap dm <- ResolverConf { rcRDataMap = dm }

-- | Get the resolvers effective RData decoder map combining the built-in and
-- user-specified maps.
{-# COMPLETE ResolverConfOptionMap #-}
pattern ResolverConfOptionMap :: OptionMap -> ResolverConf
pattern ResolverConfOptionMap om <- ResolverConf { rcOptnMap = om }

-- | Returns the user-specified RData decoder map, specified with
-- 'setResolverConfRDataMap'.
getResolverConfRDataMap :: ResolverConf -> RDataMap
getResolverConfRDataMap = userRDataMap

-- | Extend the resolver's RData decoder map, with handlers for additional
-- RRtypes.  This can only add new RRtypes, the built-in decoders take
-- precedence.
--
setResolverConfRDataMap :: RDataMap -> ResolverConf -> ResolverConf
setResolverConfRDataMap dm ResolverConf {..} =
    ResolverConf {userRDataMap = dm, rcRDataMap = baseCodecs <> dm, ..}

-- | Returns the user-specified EDNS option decoder map, specified with
-- 'setResolverConfOptionMap'.
getResolverConfOptionMap :: ResolverConf -> OptionMap
getResolverConfOptionMap = userOptnMap

-- | Extend the resolver's EDNS option decoder map, with handlers for
-- additional options.  This can only add new options, the built-in decoders
-- take precedence.
--
setResolverConfOptionMap :: OptionMap -> ResolverConf -> ResolverConf
setResolverConfOptionMap om ResolverConf {..} =
    ResolverConf {userOptnMap = om, rcOptnMap = baseOptions <> om, ..}

-- | Update Options for existing Known type.
resolverCodecParamUpdate :: forall a proxy. KnownRData a
                         => proxy a
                         -> CodecOpts a
                         -> ResolverConf
                         -> Maybe ResolverConf
resolverCodecParamUpdate _ (more :: CodecOpts a) rc
    | Just (SomeCodec (q :: Proxy b) (old :: CodecOpts b)) <- val
    , Just R.Refl <- R.testEquality (R.typeRep @a) (R.typeRep @b)
    , new <- optUpdate @a old more
    , entry <- SomeCodec q new
    , kvm' <- IM.insert key entry kvm = Just $! rc { rcRDataMap = kvm' }
    | otherwise                       = Nothing
  where
    key = fromIntegral @Word16 . coerce $ rdType @a
    kvm = rcRDataMap rc
    val = IM.lookup key kvm


-- |  Make a 'ResolvSeed' from a 'ResolvConf'.
--
--    Examples:
--
--    >>> rs <- runExceptT $ makeResolvSeed defaultResolvConf
--
makeResolvSeed :: ResolverConf -> DNSIO ResolvSeed
makeResolvSeed conf = ResolvSeed conf <$> findAddresses
  where
    findAddresses :: DNSIO (NonEmpty Nameserver)
    findAddresses = case rcSource conf of
        HostList rs     -> join <$> mapM getNameserverAddresses rs
        SourceFile file -> getDefaultNameservers file >>= mkAddrs

    getNameserverAddresses (NameserverSpec h mp) = makeAddrInfo (Just h) mp

    -- When /etc/resolv.conf contains no addresses, default to the loopback address,
    -- by by passing 'Nothing' for the server name.
    mkAddrs []     = makeAddrInfo Nothing Nothing
    mkAddrs (l:ls) = join <$> mapM getNameserverAddresses (l :| ls)


-- | Default resolver configuration, with nameserver list from
-- @\/etc\/resolv.conf@.
defaultResolvConf :: ResolverConf
defaultResolvConf = ResolverConf {
    rcTimeout       = 3_000_000 -- 3 seconds
  , rcRetries       = 3
  , rcSource        = SourceFile "/etc/resolv.conf"
  , rcQryCtls       = mempty
  , rcRDataMap      = baseCodecs
  , rcOptnMap       = baseOptions
  , userRDataMap    = IM.empty
  , userOptnMap     = IM.empty
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

-- | Giving a thread-safe 'Resolver' to the function of the second
--   argument.
withResolver :: ResolvSeed -> (Resolver -> DNSIO a) -> DNSIO a
withResolver seed f = lift (makeResolver seed) >>= flip catchE throwE . f

-- | Create a thread-specific 'Resolver' from an input 'ResolvSeed'
makeResolver :: ResolvSeed -> IO Resolver
makeResolver resolvSeed = do
    resolvRng <- fmap getRandom $ C.drgNew >>= I.newIORef
    pure Resolver{..}
  where
    getRandom :: IORef C.ChaChaDRG -> IO Word16
    getRandom ref = do
        gen <- I.readIORef ref
        let (bs, gen') = C.randomBytesGenerate 2 gen
            !seqno = word16be bs
        seqno <$ I.writeIORef ref gen'

---------- RRTYPE lookups

-- | Mapping from 'RRTYPE' name to 'RRTYPE'.
newtype RRtypeNames = RRNames_ (M.Map SB.ShortByteString RRTYPE)

-- | Attempt to find an 'RRTYPE' by name.  The lookup map can be constructed
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

-- | Construct a map of type names to 'RRTYPE'. If a resolver configuration is
-- provided include its registered types, followed by the built-in types.
confTypeNames :: Maybe ResolverConf -> RRtypeNames
confTypeNames cnf =
    coerce $ maybe M.empty cnfMap cnf <> M.fromList knownNames
  where
    cnfMap (ResolverConf{..}) =
        M.fromList $ map (uncurry mkPair) $ IM.toList rcRDataMap
      where
        mkPair k (SomeCodec p _) =
            (proxyName p, RRTYPE $ fromIntegral k)
        proxyName :: forall a. KnownRData a
                  => Proxy a -> SB.ShortByteString
        proxyName _ = buildShort $ rdTypePres @a mempty

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
