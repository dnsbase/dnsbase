{-|
Module      : Net.DNSBase.RData.SVCB
Description : Service Binding (SVCB) and HTTPS resource records
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable

The Service Binding RR ('T_svcb') and its HTTPS-specific
variant ('T_https'), defined by RFC 9460.  Both share a wire
format with three fields — priority, target name, and a list
of typed (key, value) service parameters — represented
internally by the 'X_svcb' data type, indexed by a type-level
natural that determines the specific RR type.

The service-parameter machinery is split across submodules:

* "Net.DNSBase.RData.SVCB.SVCParamKey" — the 16-bit key codes,
  with pattern synonyms for the registered keys.
* "Net.DNSBase.RData.SVCB.SVCParamValue" — the
  'KnownSVCParamValue' typeclass, the existential
  'SVCB.SVCParamValue' wrapper, and the 'OpaqueSPV' fallback for
  unrecognised keys.
* "Net.DNSBase.RData.SVCB.SPV" — the concrete value types
  ('Net.DNSBase.RData.SVCB.SPV_alpn',
  'Net.DNSBase.RData.SVCB.SPV_port', ...).
* "Net.DNSBase.RData.SVCB.SPVSet" — the (key-indexed)
  collection holding the parameters of a single SVCB/HTTPS
  record.

New service-parameter value types can be installed at runtime via
'Net.DNSBase.Resolver.extendRRwithType' on the @SVCB@ or @HTTPS@
RR type — see "Net.DNSBase.Extensible" for a worked example.  The
@mandatory@ key (codepoint 0) is reserved and cannot be replaced
by user code.
-}
{-# LANGUAGE
    MagicHash
  , RecordWildCards
  , UndecidableInstances
  #-}
{-# OPTIONS_GHC -Wno-duplicate-exports #-}

module Net.DNSBase.RData.SVCB
    ( -- * SVCB and HTTPS
      X_svcb(.., T_SVCB, T_HTTPS
            , httpsPriority, httpsTarget, httpsParamValues
            , svcPriority, svcTarget, svcParamValues)
    , type XsvcbConName
      -- *** @T_HTTPS@ pattern record synonym fields
    , T_https
    , httpsPriority, httpsTarget, httpsParamValues
      -- *** @T_SVCB@ pattern record synonym fields
    , T_svcb
    , svcPriority, svcTarget, svcParamValues
      -- ** Service parameter values
    , KnownSVCParamValue(..)
    , SPVSet(..)
    , spvLookup
    , module Net.DNSBase.RData.SVCB.SPV
    , module Net.DNSBase.RData.SVCB.SVCParamValue
    , module Net.DNSBase.RData.SVCB.SVCParamKey
    ) where

import qualified Data.IntMap as IM
import Data.IntMap (IntMap)
import GHC.Exts (proxy#)
import GHC.IsList(IsList(..))
import GHC.TypeLits as TL (TypeError, ErrorMessage(..))
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal')

import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Nat16
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RData.SVCB.SPV
import Net.DNSBase.RData.SVCB.SVCParamKey
import Net.DNSBase.RData.SVCB.SVCParamValue
import Net.DNSBase.RData.SVCB.SPVSet (SPVSet(..), spvSetFromMonoList, spvLookup)
import Net.DNSBase.RRTYPE

type XsvcbConName :: Nat -> Symbol
type family XsvcbConName n where
    XsvcbConName N_svcb  = "T_SVCB"
    XsvcbConName N_https = "T_HTTPS"
    XsvcbConName n       = TypeError
                           ( ShowType n
                             :<>: TL.Text " is not a SVCB-based RRTYPE" )

-- | Each parameter decoder is responsible for deserialising just the value
-- part of the service parameter key-value pair, the key is already decoded and
-- used to locate the right map entry.  The input 'Int' parameter is the
-- length of the serialised data to decode.
--
type SPVDecoderMap = IntMap (Int -> SGet SVCParamValue)

-- | X_svcb specialised to @HTTPS@ records.
--
-- Note that @T_https@ is just a type alias!  The 'T_HTTPS' record pattern
-- synonym and its fields are bundled with the underlying 'X_svcb'
-- data type.  In many cases it is sufficient to import just
-- @X_svcb(..)@, but if you also need the type alias, it needs to be
-- imported separately:
--
-- > import Net.DNSBase (X_svcb(..), T_https)
--
type T_https = X_svcb N_https

-- | X_svcb specialised to @SVCB@ records.
--
-- Note that @T_svcb@ is just a type alias!  The 'T_SCVB' record pattern
-- synonym and its fields are bundled with the underlying 'X_svcb'
-- data type.  In many cases it is sufficient to import just
-- @X_svcb(..)@, but if you also need the type alias, it needs to be
-- imported separately:
--
-- > import Net.DNSBase (X_svcb(..), T_svcb)
--
type T_svcb  = X_svcb N_svcb

-- | Record pattern synonym viewing the shared 'X_svcb' record as
-- an HTTPS service-binding record (RFC 9460).  Fields:
-- 'httpsPriority', 'httpsTarget', 'httpsParamValues'.
pattern T_HTTPS :: Word16 -- ^ SvcPriority
                -> Domain -- ^ TargetName
                -> SPVSet -- ^ SvcParams
                -> T_https
pattern T_HTTPS { httpsPriority, httpsTarget, httpsParamValues }
      = (X_SVCB httpsPriority httpsTarget httpsParamValues :: T_https)
{-# COMPLETE T_HTTPS #-}

-- | Record pattern synonym viewing the shared 'X_svcb' record as a
-- generic SVCB service-binding record (RFC 9460).  Fields:
-- 'svcPriority', 'svcTarget', 'svcParamValues'.  See 'X_svcb' for
-- why 'T_svcb' and 'T_https' are not coercible.
pattern T_SVCB :: Word16 -- ^ SvcPriority
               -> Domain -- ^ TargetName
               -> SPVSet -- ^ SvcParams
               -> T_svcb
pattern T_SVCB { svcPriority, svcTarget, svcParamValues }
      = (X_SVCB svcPriority svcTarget svcParamValues :: T_svcb)
{-# COMPLETE T_SVCB #-}

-- | Shared wire-format representation for the @SVCB@ service
-- binding record
-- ([RFC 9460 section 2](https://datatracker.ietf.org/doc/html/rfc9460#section-2))
-- and its HTTPS-specific variant
-- ([RFC 9460 section 9](https://datatracker.ietf.org/doc/html/rfc9460#section-9)).
--
-- >                                 1  1  1  1  1  1
-- >   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                  SvcPriority                  |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                  TargetName                   /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                   SvcParams                   /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The type parameter @n@ (either 'N_https' or 'N_svcb')
-- determines the RR type.  Each has its own type synonym
-- ('T_https', 'T_svcb') and matching record pattern synonym
-- ('T_HTTPS', 'T_SVCB') with the corresponding field-name prefix
-- (@https@, @svcb@).  The wire format is shared, but the type
-- role of @n@ is @nominal@: a 'T_svcb' value cannot be used where
-- a 'T_https' is expected.  This is deliberate — the two RR types
-- serve different transports, and future SvcParamKeys may apply
-- to only one of them.
--
-- Note that @T_https@ and @T_svcb@ are just type aliases!  The 'T_HTTPS'
-- and 'T_SVCB' record pattern synonyms and their fields are
-- bundled with the underlying 'X_svcb' data type.  In many cases it
-- is sufficient to import just @X_svcb(..)@, but if you also need
-- the type aliases, they need to be imported separately:
--
-- > import Net.DNSBase (X_svcb(..), T_https, T_svcb)
--
-- The target field is not subject to wire-form name compression
-- ([RFC 3597 section 4](https://datatracker.ietf.org/doc/html/rfc3597#section-4))
-- and is /not/ in the
-- [RFC 4034 section 6.2](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2)
-- list of types that lower-case their RDATA names — it is
-- compared case-sensitively in canonical form.  The 'Ord'
-- instance compares structurally on the parsed fields rather
-- than on the wire form, so it is /not/ canonical: callers that
-- need RFC 4034 canonical ordering must serialise to wire form
-- first.
--
-- The /SvcParams/ field is a list of @(key, length, value)@
-- triples — possibly empty — making up the rest of the RData:
--
-- >                                 1  1  1  1  1  1
-- >   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                  SvcParamKey                  |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                  SvcParamLen                  |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > /                  SvcParamValue                /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- On the wire the list must be in strictly ascending key order;
-- the presentation form may list keys in any order.  Each value
-- has the type associated with its key in the decoder state
-- configured for the RR type — keys absent from the state decode
-- as 'OpaqueSPV', preserving the raw bytes.
--
-- The record pattern synonyms 'T_SVCB' and 'T_HTTPS' build the
-- corresponding 'T_svcb' or 'T_https' value directly, with their
-- own field-name prefixes (@svc@ and @https@):
--
-- > let s = T_SVCB  { svcPriority      = 0
-- >                 , svcTarget        = RootDomain
-- >                 , svcParamValues   = [] }
-- >     h = T_HTTPS { httpsPriority    = 0
-- >                 , httpsTarget      = RootDomain
-- >                 , httpsParamValues = [] }
-- >  in RData s : RData h : []
--
-- Functions that work on either RR type can use the
-- underscore-prefixed selectors on the shared 'X_svcb' record:
--
-- > aliasDomain :: forall n. X_svcb n -> Maybe Domain
-- > aliasDomain r | x_svcPriority r == 0 = Just $ x_svcTarget r
-- >               | otherwise           = Nothing
type X_svcb :: Nat -> Type
type role X_svcb nominal
data X_svcb n = X_SVCB
    { x_svcPriority    :: Word16 -- ^ SvcPriority
    , x_svcTarget      :: Domain -- ^ TargetName
    , x_svcParamValues :: SPVSet -- ^ SvcParams
    }

deriving instance Eq (X_svcb n)

instance (KnownSymbol (XsvcbConName n)) => Show (X_svcb n) where
    showsPrec p X_SVCB{..} = showsP p $
        showString (symbolVal' (proxy# @(XsvcbConName n))) . showChar ' '
        . shows' x_svcPriority    . showChar ' '
        . shows' x_svcTarget      . showChar ' '
        . shows' x_svcParamValues

instance Ord (X_svcb n) where
    a `compare` b = (x_svcPriority a) `compare` (x_svcPriority b)
                 <> (x_svcTarget   a) `compare` (x_svcTarget   b)
                 <> (spvs         a) `compare` (spvs         b)
      where
        spvs = toList . x_svcParamValues

instance Presentable (X_svcb n) where
    present (X_SVCB p d vs)  =
        present p . presentSp d . flip (foldr presentSp) (toList vs)

instance (Nat16 n, KnownSymbol (XsvcbConName n)) => KnownRData (X_svcb n) where
    type RDataExtensionVal (X_svcb n) = SPVDecoderMap
    rdataExtensionVal _ = baseSVCParams

    rdType _ = RRTYPE $ natToWord16 n
    rdEncode (X_SVCB p d vs) = do
        putSizedBuilder $ mbWord16 p <> mbWireForm d
        mapM_ enc $ toList vs
      where
        enc (SVCParamValue (x :: t)) = do
            put16 $ coerce $ spvKey t
            passLen $ encodeSPV x
    -- The resolver serice parameter extension slots for @T_svcb@
    -- and @T_https@ are configured with the table of known parameters
    -- and can be extended at runtime as part of resolver configuration.
    rdDecode _ sdm len = do
        pos0            <- getPosition
        x_svcPriority    <- get16
        x_svcTarget      <- getDomainNC
        pos1            <- getPosition
        vals            <- decodeSVCFieldValues (len - (pos1 - pos0))
        let x_svcParamValues = spvSetFromMonoList $ reverse vals
        pure $ RData $ (X_SVCB{..} :: X_svcb n)
      where
        decodeSVCFieldValues :: Int -> SGet [SVCParamValue]
        decodeSVCFieldValues = fitSGet <$> id <*> loop [] 0
          where
            loop :: [SVCParamValue] -> Word16 -> Int -> SGet [SVCParamValue]
            loop acc !kmin !n | n > 0 = do
                pos0 <- getPosition
                key  <- get16
                vlen <- getInt16
                when (key == 0xffff) reserved
                when (kmin > key) $ nonmono (kmin-1) key
                spv <- case IM.lookup (fromIntegral key) sdm of
                    Just dc -> fitSGet vlen $ dc vlen
                    Nothing -> opaqueSPV key <$> getShortNByteString vlen
                used <- (subtract pos0) <$> getPosition
                loop (spv : acc) (key + 1) (n - used)
            loop acc _ 0 = pure acc
            loop _ _ _ = failSGet "internal error"

            -- 65535 is a reserved "Invalid key"
            reserved = failSGet "Reserved invalid key: 65535"
            -- Keys MUST be in strictly increasing order
            nonmono k1 k2 =
                failSGet $ "Non-increasing keys: " ++ show k1 ++ ", " ++ show k2

instance (Nat16 n, KnownSymbol (XsvcbConName n))
      => TypeExtensible (X_svcb n) SPVDecoderMap where
    type TypeExtensionArg (X_svcb n) b = KnownSVCParamValue b

    -- Insert the typed decoder at b's SvcParam key, except for the
    -- reserved @mandatory@ slot (codepoint 0), which the library
    -- owns and silently drops user attempts to replace.
    extendByType _ b m
        | key == mandatoryKey = m
        | otherwise = IM.insert key (decodeSPV b) m
      where
        key = fromIntegral @Word16 . coerce $ spvKey b

-- | Initial decoder state used as the
-- 'Net.DNSBase.RData.rdataExtensionVal' for both 'T_svcb' and
-- 'T_https'.  Not exported: user code interacts with it through
-- 'Net.DNSBase.Resolver.extendRRwithType', which calls
-- 'extendByType' to insert additional 'KnownSVCParamValue'
-- decoders.
baseSVCParams :: SPVDecoderMap
baseSVCParams = IM.fromList
    [ spvMapEntry SPV_mandatory
    , spvMapEntry SPV_alpn
    , spvMapEntry SPV_ndalpn
    , spvMapEntry SPV_port
    , spvMapEntry SPV_ipv4hint
    , spvMapEntry SPV_ech
    , spvMapEntry SPV_ipv6hint
    , spvMapEntry SPV_dohpath
    , spvMapEntry SPV_tlsgroups
    , spvMapEntry SPV_docpath
    , spvMapEntry SPV_pvd
    ]
  where
    spvMapEntry :: forall a -> KnownSVCParamValue a
                => (Int, Int -> SGet SVCParamValue)
    spvMapEntry a =
        ( fromIntegral @Word16 . coerce $ spvKey a
        , decodeSPV a)

-- Numeric SvcParamKey for the @mandatory@ key; protected from
-- user override inside 'extendByType'.
mandatoryKey :: Int
mandatoryKey = fromIntegral @Word16 . coerce $ spvKey SPV_mandatory
