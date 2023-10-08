# Base DNS library with extensible core types

DNS library with an extensible set of DNS RRtypes, EDNS options and HTTPS and
SVCB RR field keys and values.  Applications can augment the library with
new RR types, ... and corresponding encoders and decoders.

Some parts of the library (in particular the IO layer) are to various extents
based on original code from Kazu Yamamoto's "dns" library.

This library is an early work-in-progress, no expectation of stability or
reliability.

## Basic MX lookup example

The demo program (simpe.hs) below will print the MX records of "ietf.org", if
any, or print an error message if there's a problem obtaining the answer.

```haskell
{-# LANGUAGE
    BlockArguments
  , RecordWildCards
  , TemplateHaskell
  #-}
import Control.Exception (throwIO)
import Control.Monad.Trans.Except (runExceptT)
import Net.DNSBase
import System.IO (stdout)

main :: IO ()
main = do
    seed <- either throwIO pure =<< runExceptT do
                makeResolvSeed defaultResolvConf
    mxs  <- either throwIO pure =<< runExceptT do
                withResolver seed \r -> lookupMX r $$(dnLit "ietf.org")
    hPutBuilder stdout $ foldr presentLn mempty mxs
```

## Advanced RP lookup example

The demo program below (extensible.hs) will print the RP RRset of "imdb.com",
and the HTTPS RRset of "cloudflare.com", whichever are available, or print an
error message if there's a problem obtaining both results.  The RP RRset is not
(yet) built-in to the library, this example adds the necessary support.

The set of supported SVCB parameters is also runtime extensible, as is the set
of supported EDNS options.  Anything not explicitly understood, is decoded as
opaque data, of the appropriate sort.

You can customise the DNS/EDNS flags sent in requests and any EDNS parameters
and options.

```haskell
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
import Data.Typeable (Typeable)
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
    } deriving (Typeable, Eq, Ord, Show)

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
    rdType     = EXT_RP
    -- String required, a novel RRTYPE itself would (if it were not already
    -- built-in) present as @TYPE@/nnnn/.
    rdTypePres = present @String "RP"
    rdEncode T_EXT_RP{..} = putSizedBuilder $
        -- <https://datatracker.ietf.org/doc/html/rfc3597#section-4>, not
        -- subject to name compression on output, tolerated when decoding.
        mbWireForm ext_rp_mbox
        <> mbWireForm ext_rp_domain
    rdDecode _ = const do
        ext_rp_mbox <- getDomain
        ext_rp_domain <- getDomain
        return $ RData T_EXT_RP{..}

-- The resulting resolver configuration knows how to decode and encode RP
-- records.
withRP :: ResolverConf -> ResolverConf
withRP = setResolverConfRDataMap rdmap
  where
    rdmap = uncurry IM.singleton $ rdataMapEntry @T_ext_rp ()

---------

main :: IO ()
main = do
    -- Resolver activity happens in DNSIO == ExceptT DNSError IO It would be
    -- reasonable and typical to just wrap the resolver calls in ExceptT,
    -- checking for Left/Right results, rather than run the whole application
    -- in DNSIO.
    --
    seed <- either throwIO pure =<< runExceptT do
                makeResolvSeed do withRP defaultResolvConf
    outf <- either throwIO pure =<< runExceptT do
                withResolver seed \r -> do
                    rps <- getanswers EXT_RP r $$(dnLit "imdb.com")
                    -- The set of supported SVCB parameters is also extensible,
                    -- as is the set of supported EDNS options.  Anything not
                    -- explicitly understood, is decoded as opaque data, of the
                    -- appropriate sort.
                    hts <- getanswers HTTPS r $$(dnLit "cloudflare.com")
                    pure $ presentRRset rps
                         . presentLn ';'
                         . presentRRset hts
    hPutBuilder stdout $ outf mempty
  where
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
```
