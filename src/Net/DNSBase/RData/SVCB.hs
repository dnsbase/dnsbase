{-# LANGUAGE
    CPP
  , RecordWildCards
  , UndecidableInstances
  #-}
module Net.DNSBase.RData.SVCB
    ( -- * SVCB and HTTPS
      X_svcb(.., T_SVCB, T_HTTPS)
    , T_svcb
    , T_https
      -- * Defining parameters at runtime
    , SPVDecoderMap
      -- Representation of unknown parameters
    , OpaqueSPV(..)
    ) where

import qualified Data.ByteString.Short as SB
import qualified Data.IntMap as IM
import Data.IntMap (IntMap)
#if MIN_VERSION_base(4,17,0)
import GHC.IsList(IsList(..))
#else
import GHC.Exts(IsList(..))
#endif
import GHC.TypeLits (TypeError, ErrorMessage(..))
import GHC.TypeLits (KnownSymbol, Symbol, symbolVal)

import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.Domain
import Net.DNSBase.Decode.State
import Net.DNSBase.Domain
import Net.DNSBase.Encode.Metric
import Net.DNSBase.Encode.State
import Net.DNSBase.Nat16
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RData.SVCB.SPVSet (SPVSet)
import Net.DNSBase.RData.SVCB.SVCParamKey
import Net.DNSBase.RData.SVCB.SVCParamValue
import Net.DNSBase.RRTYPE
import Net.DNSBase.Text

type XsvcbConName :: Nat -> Symbol
type family XsvcbConName n where
    XsvcbConName N_svcb  = "T_SVCB"
    XsvcbConName N_https = "T_HTTPS"
    XsvcbConName n       = TypeError
                           ( ShowType n
                             :<>: Text " is not a SVCB-based RRTYPE" )

-- | Each parameter decoder is responsible for deserialising just the value
-- part of the service parameter key-value pair, the key is already decoded and
-- used to locate the right map entry.  The input 'Int' parameter is the
-- length of the serialised data to decode.
type SPVDecoderMap = IntMap (Int -> SGet SVCParamValue)

-- | @SVCB@ and @HTTPS@ RData are structurally identical.
type T_svcb  = X_svcb N_svcb
type T_https = X_svcb N_https

-- | Interpret an 'X_svcb' structure of type @SVCB@ as a 'T_svcb'.
{-# COMPLETE T_SVCB #-}
pattern  T_SVCB :: Word16 -> Domain -> SPVSet ->  T_svcb
pattern  T_SVCB p d vs = (X_SVCB p d vs ::  T_svcb)
-- | Interpret an 'X_svcb' structure of type @HTTPS@ as a 'T_https'.
{-# COMPLETE T_HTTPS #-}
pattern T_HTTPS :: Word16 -> Domain -> SPVSet -> T_https
pattern T_HTTPS p d vs = (X_SVCB p d vs :: T_https)

-- | [SVCB RDATA](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-12#section-2)
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
-- The target domain name is not subject to
-- [name compression](https://datatracker.ietf.org/doc/html/rfc3597#section-4),
-- and canonicalises
-- [as-is](https://datatracker.ietf.org/doc/html/rfc4034#section-6.2).
--
-- The 'Ord' instance is not canonical.  Canonical ordering requires
-- serialisation to canonical wire form.
--
-- The ServiceParams is a possibly empty list of (generally not 16-bit aligned)
-- elements of the form below, that occupy the rest of the SVCB RData.  The
-- wire form for the list must be in strictly ascending key order.  The
-- presentation of the key-value pairs can be in any order.
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
-- Can equally hold @HTTPS@ RR data and is mutually coercible between the two
-- concrete types.  The shared constructor supports record syntax:
--
-- > let s :: T_svcb
-- >     s = X_SVCB { svcPriority    = 0
-- >                , svcTarget      = RootDomain
-- >                , svcParamValues = [] }
-- >     h :: T_https
-- >     h = X_SVCB { svcPriority    = 0
-- >                , svcTarget      = RootDomain
-- >                , svcParamValues = [] }
--
-- But the result type must generally either, be specified explicitly, or be
-- possible to infer from context.  In the example below, the explicit type is
-- not optional, because @RData rd@ could hold either type.
--
-- > let rd :: T_svcb
-- >     rd = X_SVCB { svcPriority = 0
-- >                 , svcTarget = RootDomain
-- >                 , svcParamValues = [] }
-- >  in RData rd
--
-- Functions that are agnostic of the underlying type can be written as:
--
-- > aliasDomain :: forall n. X_svcb n -> Maybe Domain
-- > aliasDomain r | svcPriority r == 0 = Just $ svcTarget r
-- >               | otherwise          = Nothing
--
-- This is an extensible datatype, with optional structured key/value pairs
-- that can be defined in follow-on RFCs.  Proper typing of the key/value pairs
-- is via existential quantification, just as with the 'RData' elements of an
-- 'RR'.  Unrecognised keys and their values are encoded and decoded as
-- 'OpaqueSPV' (service parameter value) data.
--
-- Just as with 'RData', each concrete 'SVCParamValue' type is bound to its
-- associated key as a constant the typeclass instance.
--
type X_svcb :: Nat -> Type
type role X_svcb phantom
data X_svcb n = X_SVCB
    { svcPriority    :: Word16
    , svcTarget      :: Domain
    , svcParamValues :: SPVSet }

deriving instance Typeable (X_svcb n)
deriving instance Eq (X_svcb n)

instance (KnownSymbol (XsvcbConName n)) => Show (X_svcb n) where
    showsPrec p X_SVCB{..} = showsP p $
        showString (symbolVal (Proxy @(XsvcbConName n))) . showChar ' '
        . shows' svcPriority    . showChar ' '
        . shows' svcTarget      . showChar ' '
        . shows' svcParamValues

instance Ord (X_svcb n) where
    a `compare` b = (svcPriority a) `compare` (svcPriority b)
                 <> (svcTarget   a) `compare` (svcTarget   b)
                 <> (spvs        a) `compare` (spvs        b)
      where
        spvs = toList . svcParamValues

instance Presentable (X_svcb n) where
    present (X_SVCB p d vs)  =
        present p . presentSp d . flip (foldr presentSp) (toList vs)

instance (Nat16 n, KnownSymbol (XsvcbConName n)) => KnownRData (X_svcb n) where
    type CodecOpts (X_svcb n) = SPVDecoderMap
    optUpdate _ base more = base <> more

    rdType _ = RRTYPE $ natToWord16 @n
    rdEncode (X_SVCB p d vs) = do
        putSizedBuilder $ mbWord16 p <> mbWireForm d
        mapM_ enc $ toList vs
      where
        enc (SVCParamValue (x :: t)) = do
            put16 $ coerce $ spvKey @t
            encodeSPV x
    -- The resolver 'RDataMap' slots for @T_svcb@
    -- and @T_https@ are configured with the table of known parameters and can be
    -- extended at runtime as part of resolver configuration.
    rdDecode _ sdm len = do
        pos0           <- getPosition
        svcPriority    <- get16
        svcTarget      <- getDomainNC
        pos1           <- getPosition
        vals           <- decodeSVCFieldValues (len - (pos1 - pos0))
        let svcParamValues = fromList vals
        pure $ RData $ (X_SVCB{..} :: X_svcb n)
      where
        decodeSVCFieldValues :: Int -> SGet [SVCParamValue]
        decodeSVCFieldValues = getVarWidthSequence decodeSVCParamValue

        decodeSVCParamValue :: SGet SVCParamValue
        decodeSVCParamValue = do
            key  <- get16
            vlen <- getInt16
            case IM.lookup (fromIntegral key) sdm of
                Just dc -> fitSGet vlen $ dc vlen
                Nothing -> opaqueSPV key <$> getShortNByteString vlen

-- | Opaque (i.e. unknown) ParamKey

data OpaqueSPV n where
     OpaqueSPV :: Nat16 n => SB.ShortByteString -> OpaqueSPV n
deriving instance Typeable (OpaqueSPV n)
deriving instance Eq (OpaqueSPV n)
deriving instance Ord (OpaqueSPV n)
deriving instance Show (OpaqueSPV n)

instance Nat16 n => KnownSVCParamValue (OpaqueSPV n) where
    spvKey = SVCParamKey $ natToWord16 @n
    encodeSPV (OpaqueSPV txt) = putShortByteStringLen16 txt
    decodeSPV len = do
        txt <- getShortNByteString len
        pure $ SVCParamValue (OpaqueSPV txt :: OpaqueSPV n)

instance Nat16 n => Presentable (OpaqueSPV n) where
    present (OpaqueSPV v) =
        spvKeyPres @(OpaqueSPV n)
        -- Empty values suppressed
        . bool id (presentCharSep @DnsText '=' (coerce v)) ((SB.length v) > 0)

-- | Construct an explicit 'OpaqueSPV' service parameter key value pair from
-- the raw numeric key and short bytestring value.
opaqueSPV :: Word16 -> SB.ShortByteString -> SVCParamValue
opaqueSPV (wordToNat16 -> SomeNat16 (_ :: proxy n)) bs =
    SVCParamValue $ (OpaqueSPV bs :: OpaqueSPV n)
