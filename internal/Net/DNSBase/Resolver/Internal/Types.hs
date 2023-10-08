{-# LANGUAGE RecordWildCards #-}
module Net.DNSBase.Resolver.Internal.Types
     (
     -- * Static resolver configuration
       ResolverConf(..)
     , NameserverConf(..)
     , NameserverSpec(..)
     -- ** Derived resolver objects
     , ResolvSeed(..)
     , Resolver(..)
     , Nameserver(..)
     -- ** Resolver control structures
     , RDataMap
     , OptionMap
     , QueryControls(
         QctlFlags
       , QctlEdns
       , EdnsEnabled
       , EdnsDisabled
       , EdnsVersion
       , EdnsUdpSize
       , EdnsOptionCtl
       )
     -- * Resolver Monad
     , DNSIO
     , makeQueryFlags
     ) where

import Data.List (intercalate)
import Network.Socket (AddrInfo(..), PortNumber)

import Net.DNSBase.Decode.Internal.Option
import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.Internal.EDNS
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Flags
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.Util

type DNSIO = ExceptT DNSError IO

-- | Type for resolver configuration
data ResolverConf = ResolverConf
    { rcSource     :: NameserverConf -- ^ Resolver configuration file or list of remote sources
    , rcTimeout    :: Int            -- ^ Timeout in microseconds
    , rcRetries    :: Int            -- ^ Number of (re)tries (including the first attempt)
    , rcQryCtls    :: QueryControls  -- ^ Query and Codec Controls
    , rcRDataMap   :: RDataMap       -- ^ Known RData codecs
    , rcOptnMap    :: OptionMap      -- ^ Known EDNS Option codecs
    , userRDataMap :: RDataMap       -- ^ Custom RData codecs
    , userOptnMap  :: OptionMap      -- ^ Custom EDNS Option codecs
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

-- | Resolver configuration augmented with server addresses corresponding to
-- the configured IP address strings and/or hostnames.  This can be passed to
-- 'withResolver' to obtain a thread-specific resolver handle.
--
data ResolvSeed = ResolvSeed
    { seedConfig  :: ResolverConf
    , seedServers :: NonEmpty Nameserver
    }

-- | Internal DNS Resolver handle, obtained via 'withResolver'. 
-- Must not be used concurrently in multiple threads.  
--
data Resolver = Resolver
    { resolvSeed :: ResolvSeed
    , resolvRng  :: IO Word16
    }

----------------------------------------------------------------

-- * Query control monoids

-- | Query controls consisting of an endomorphism over 'FlagOps' to modify
-- DNS flag bits, and an 'EDNSControls' structure to configure EDNS
-- behavior.
--
-- Constitutes a 'Monoid' with left-biased mappend operation
data QueryControls = QueryControls (FlagOps -> FlagOps) EDNSControls

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
pattern QctlFlags :: (FlagOps -> FlagOps) -> QueryControls
pattern QctlFlags fl <- QueryControls fl _ where
    QctlFlags fl = QueryControls fl mempty
{-# COMPLETE QctlFlags #-}

-- | Return the results of applying the flag query controls to the default
-- query flags, setting or clearing the requested flag bits.
makeQueryFlags :: QueryControls -> DNSFlags
makeQueryFlags (QctlFlags op) = applyFlagOps (op emptyFlagOps) defaultQueryFlags

pattern QctlEdns :: EDNSControls -> QueryControls
pattern QctlEdns edns <- QueryControls _ edns where
    QctlEdns edns = QueryControls id edns
{-# COMPLETE QctlEdns #-}

-- | EDNS query controls.  When EDNS is disabled via @ednsEnabled FlagClear@,
-- all the other EDNS-related overrides have no effect. Semigroup append is
-- left-biased
data EDNSControls = EDNSControls
    (Maybe Bool)             -- ^ Enabled
    (Maybe Word8)            -- ^ Version
    (Maybe Word16)           -- ^ UDP Size
    (OptionCtl -> OptionCtl) -- ^ EDNS option list tweaks

instance Semigroup EDNSControls where
    (EDNSControls en1 vn1 sz1 od1) <> (EDNSControls en2 vn2 sz2 od2) =
        EDNSControls (en1 <|> en2) (vn1 <|> vn2) (sz1 <|> sz2) (od1 . od2)

instance Monoid EDNSControls where
    mempty = EDNSControls Nothing Nothing Nothing id

instance Show EDNSControls where
    show (EDNSControls en vn sz od) =
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

pattern EdnsEnabled :: QueryControls
pattern EdnsEnabled <-
    QueryControls _ (EDNSControls (Just True) _ _ _) where
    EdnsEnabled = QueryControls id (EDNSControls (Just True) Nothing Nothing id)

pattern EdnsDisabled :: QueryControls
pattern EdnsDisabled <-
    QueryControls _ (EDNSControls (Just False) _ _ _) where
    EdnsDisabled = QueryControls id (EDNSControls (Just False) Nothing Nothing id)

pattern EdnsVersion :: Word8 -> QueryControls
pattern EdnsVersion vn <-
    QueryControls _ (EDNSControls _ (Just vn) _ _) where
    EdnsVersion vn = QueryControls id (EDNSControls Nothing (Just vn) Nothing id)

pattern EdnsUdpSize :: Word16 -> QueryControls
pattern EdnsUdpSize sz <-
    QueryControls _ (EDNSControls _ _ (Just sz) _) where
    EdnsUdpSize sz = QueryControls id (EDNSControls Nothing Nothing (Just capped) id)
      where
        !capped = max minUdpSize . min maxUdpSize $ sz

{-# COMPLETE EdnsOptionCtl #-}
pattern EdnsOptionCtl :: (OptionCtl -> OptionCtl) -> QueryControls
pattern EdnsOptionCtl omod <-
    QueryControls _ (EDNSControls _ _ _ omod) where
    EdnsOptionCtl omod = QueryControls id (EDNSControls Nothing Nothing Nothing omod)
