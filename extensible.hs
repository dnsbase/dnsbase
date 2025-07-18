{-# LANGUAGE
    BlockArguments
  , RecordWildCards
  , TemplateHaskell
  , TypeApplications
  #-}
import qualified Data.IntMap.Strict as IM
import Control.Exception (throwIO)
import Control.Monad.Trans.Except (runExceptT)
import Data.Coerce (coerce)
import Data.Proxy (Proxy(..))
import System.IO (stdout)

import Net.DNSBase
import Net.DNSBase.Decode.Domain

--------- Application-added @RP@ RData type
-- Use @ext\_@ and @EXT\_@ prefixes to avoid clashes with future library
-- updates.

-- | Responsible Person (RFC1183)
-- Note: The derived 'Ord' instance is not canonical.
--
pattern EXT_RP :: RRTYPE; pattern EXT_RP = RRTYPE 17

-- | The RData constructors are all T_/UPPER/, and the structure type names are
-- all T_/lower/, this reduces ambiguity, and leaves room for pattern synonyms
-- to not clash with the types.
data T_ext_rp = T_EXT_RP
    { ext_rp_mbox   :: Domain
    , ext_rp_domain :: Domain
    } deriving (Eq, Ord, Show)

-- | DO NOT use @('<>')@ with 'present', the Prelude instance for
--
-- > Semigroup m => Semigroup (a -> m)
--
-- allows that form to typecheck, but yields unexpected results.
--
instance Presentable T_ext_rp where
    present T_EXT_RP{..} =
        -- Non-standard, more user-friendly mailbox form
        present (toMbox ext_rp_mbox)
        . presentSp ext_rp_domain

-- | That's all you need to plug in a new datatype.  Once DNSSEC-validation
-- is implemented, there would need to be a canonicalisation method, that
-- knows which domain names are changed to lower-case for signing and
-- validation.
--
instance KnownRData T_ext_rp where
    rdType _ = EXT_RP
    -- String required, a novel RRTYPE itself would (if it were not already
    -- built-in) present as @TYPE@/nnnn/.
    rdTypePres _ = present @String "RP"
    rdEncode T_EXT_RP{..} = putSizedBuilder $
        -- <https://datatracker.ietf.org/doc/html/rfc3597#section-4>, not
        -- subject to name compression on output, tolerated when decoding.
        mbWireForm ext_rp_mbox
        <> mbWireForm ext_rp_domain
    rdDecode _ _ = const do
        ext_rp_mbox <- getDomain
        ext_rp_domain <- getDomain
        return $ RData T_EXT_RP{..}

-- The resulting resolver configuration knows how to decode and encode RP
-- records.
withRP :: ResolverConf -> ResolverConf
withRP = setResolverConfRDataMap rdmap
  where
    rdmap = uncurry IM.singleton $ rdataMapEntry @T_ext_rp ()

--------- Application-added @SVCB@ key type

data SPV_EXT_ohttp = SPV_EXT_OHTTP
    deriving (Eq, Ord, Show)

instance Presentable SPV_EXT_ohttp where
    present SPV_EXT_OHTTP = present "ohttp"

instance KnownSVCParamValue SPV_EXT_ohttp where
    spvKey _ = SVCParamKey 8
    encodeSPV SPV_EXT_OHTTP = pure ()
    decodeSPV _ _ = pure $ SVCParamValue SPV_EXT_OHTTP

withOHTTP :: ResolverConf -> ResolverConf
withOHTTP rc =
    case resolverCodecParamUpdate (Proxy @T_svcb) m rc of
        Just rc' -> rc'
        _        -> rc

  where
    k = fromIntegral $ spvKey SPV_EXT_ohttp
    m = IM.singleton k (decodeSPV SPV_EXT_ohttp)

---------

main :: IO ()
main = do
    -- Resolver activity happens in DNSIO == ExceptT DNSError IO It would be
    -- reasonable and typical to just wrap the resolver calls in ExceptT,
    -- checking for Left/Right results, rather than run the whole application
    -- in DNSIO.
    --
    seed <- either throwIO pure =<< runExceptT do
                makeResolvSeed $ withExts defaultResolvConf
    outf <- either throwIO pure =<< runExceptT do
                withResolver seed \r -> do
                    rps <- getanswers EXT_RP r $$(dnLit "imdb.com")
                    -- The set of supported SVCB parameters is also extensible,
                    -- as is the set of supported EDNS options.  Anything not
                    -- explicitly understood, is decoded as opaque data, of the
                    -- appropriate sort.
                    hts <- getanswers HTTPS r $$(dnLit "cloudflare.com")
                    svs <- getanswers SVCB r $$(dnLit "_dns.dns.google")
                    pure $ presentRRset rps
                         . presentLn ';'
                         . presentRRset hts
                         . presentLn ';'
                         . presentRRset svs
    hPutBuilder stdout $ outf mempty
  where
    withExts = withOHTTP . withRP
    getanswers :: RRTYPE -> Lookup RR
    getanswers typ r dom = lookupAnswers r qctls IN typ dom
      where
        qctls = QctlFlags $ setFlagBits DOflag

-- | Demo: custom RData presentation builder override by type.
data SomePresenter =
    forall a. (KnownRData a) => SomePresenter (a -> Builder -> Builder)

-- | Present an 'RData' using any applicable custom builders.
handleData :: RData -> [SomePresenter] -> Builder -> Builder
handleData rd [] = present rd
handleData rd ((SomePresenter h) : hs) = case fromRData rd of
    Just  a -> h a
    Nothing -> handleData rd hs

-- Presentation builder API uses continuation-passing style.
presentRRset :: Foldable t => t RR -> Builder -> Builder
presentRRset = flip $ foldr presentCustom

-- | Elide TTL and RRCLASS, show mailbox fields in 'user@domain' form, and
-- censor the signature part of @RRSIG@ RRs.
presentCustom :: RR -> Builder -> Builder
presentCustom RR{..} =
    present rrOwner
    . present ' '
    . customdata rrData
    . present '\n'
  where
    customdata rd = handleData rd
        [ SomePresenter mboxSOA
        , SomePresenter mboxExtRP
        , SomePresenter mboxRP
        , SomePresenter noSIG]

    mboxSOA :: T_soa -> Builder -> Builder
    mboxSOA T_SOA{..} =
        present SOA
        . presentSp soaMname
        . presentSp (toMbox soaRname)
        . presentSp soaSerial
        . presentSp soaRefresh
        . presentSp soaRetry
        . presentSp soaExpire
        . presentSp soaMinttl

    -- | Handle our custom 'T_exp_rp' type, but since the @RP@ type is now
    -- implemented in the base library, it'll be used to decode the response.
    mboxExtRP :: T_ext_rp -> Builder -> Builder
    mboxExtRP T_EXT_RP{..} =
        present RP
        . presentSp (toMbox ext_rp_mbox)
        . presentSp ext_rp_domain

    -- | Actually handle presenting @RP@ RData.
    mboxRP :: T_rp -> Builder -> Builder
    mboxRP T_RP{..} =
        present RP
        . presentSp (toMbox rpMbox)
        . presentSp rpTxt

    -- | Present RRSIG RData without the signature.
    noSIG :: T_rrsig -> Builder -> Builder
    noSIG X_SIG{..} =
        present RRSIG
        . presentSp sigType
        . presentSp sigKeyAlg
        . presentSp sigNumLabels
        . presentSp sigTTL
        . presentEp sigExpiration
        . presentEp sigInception
        . presentSp sigKeyTag
        . presentSp sigZone
        . presentSp @String "[omitted]" -- sigValue
      where
        presentEp = presentSp @Epoch64 . coerce
