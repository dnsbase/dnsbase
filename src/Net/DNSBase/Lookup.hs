{-|
Module      : Net.DNSBase.Lookup
Description : Per-RRtype lookup functions over a 'Resolver'
Copyright   : (c) IIJ Innovation Institute Inc., 2009
              (c) Viktor Dukhovni, 2020-2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : unstable
-}
{-# LANGUAGE RecordWildCards #-}
module Net.DNSBase.Lookup
    ( Lookup
    , extractAnswers
    , lookupRawCtl
    , lookupRaw
    , lookupAnswers
    , lookupM
    , lookupM_
    , lookupX
    , lookupA
    , lookupAAAA
    , lookupAFSDB
    , lookupCAA
    , lookupCDNSKEY
    , lookupCDS
    , lookupCNAME
    , lookupDNAME
    , lookupDNSKEY
    , lookupDS
    , lookupHINFO
    , lookupHTTPS
    , lookupMX
    , lookupNS
    , lookupNSEC
    , lookupNSEC3PARAM
    , lookupNULL
    , lookupPTR
    , lookupRP
    , lookupSOA
    , lookupSRV
    , lookupSSHFP
    , lookupSVCB
    , lookupTLSA
    , lookupTXT
    , lookupZONEMD
    ) where
import qualified Data.Map.Strict as M
import Data.Foldable (foldlM)
import Data.Map.Strict (Map)
import Data.Maybe (mapMaybe)

import Net.DNSBase.Internal.Bytes
import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Message
import Net.DNSBase.Internal.RCODE
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.RR
import Net.DNSBase.Internal.Transport
import Net.DNSBase.Internal.Util
import Net.DNSBase.Resolver.Internal.Types

import Net.DNSBase.RData.A
import Net.DNSBase.RData.CAA
import Net.DNSBase.RData.Dnssec
import Net.DNSBase.RData.SOA
import Net.DNSBase.RData.SRV
import Net.DNSBase.RData.SVCB
import Net.DNSBase.RData.TLSA
import Net.DNSBase.RData.TXT
import Net.DNSBase.RData.XNAME
import Net.DNSBase.RRCLASS
import Net.DNSBase.RRSet
import Net.DNSBase.RRTYPE

-- | Shape of a typed lookup: a 'Resolver' and a query 'Domain' produce
-- either a list of answers, or a 'DNSError'.  An empty list means that
-- either the name exists and has no records of the queried type
-- (@NODATA@), or the name does not exist (@NXDOMAIN@). Both are
-- non-error outcomes.
--
type Lookup a = Resolver -> Domain -> IO (Either DNSError [a])

-- | Generic answer-RData lookup, applying a function to each
-- result.  If the the function's first argument is polymorphic, a
-- type application at the call site may be needed to make it
-- possible to determine the type of its argument.
--
lookupX :: KnownRData a => RRTYPE -> (a -> b) -> Lookup b
lookupX typ f rslv dom =
    fmap (fmap getOnly) (lookupAnswers rslv mempty IN typ dom)
  where
    getOnly = mapMaybe (f <.> rrDataCast)

-- | Apply an IO action to each lookup value and collect the
-- results. If the the action's first argument is polymorphic,
-- a type application at the call site may be needed to make it
-- possible to determine the type of its argument.
--
lookupM :: forall a b. KnownRData a => (a -> IO b) -> Lookup b
lookupM f rslv = lookupAnswers rslv mempty IN (rdType a) >=> \ case
   Left why -> pure $ Left why
   Right rrs -> Right <$> foldlM go [] rrs
 where
    go acc rr = case rrDataCast rr of
        Just rd -> do
            !b <- f rd
            pure $ b : acc
        Nothing -> pure acc

-- | Apply an IO action to each lookup value and discard the
-- results. If the the action's first argument is polymorphic, a
-- type application at the call site may be needed to make it
-- possible to determine the type of its argument.
--
lookupM_ :: forall a b. KnownRData a
         => (a -> IO b) -> Resolver -> Domain -> IO (Either DNSError ())
lookupM_ f rslv = lookupAnswers rslv mempty IN (rdType a) >=> \ case
   Left why -> pure $ Left why
   Right rrs -> Right <$> go rrs
 where
    go (rr : rest) = case rrDataCast rr of
        Just rd -> f rd >> go rest
        Nothing -> go rest
    go [] = pure ()

-- | Perform a raw lookup returning the full 'DNSMessage' or a
-- 'DNSError'.  See 'lookupRawCtl' for the variant that takes
-- per-call query controls.
--
lookupRaw :: Resolver -> Domain -> RRCLASS -> RRTYPE
          -> IO (Either DNSError DNSMessage)
lookupRaw rslv = lookupRawCtl rslv mempty

-- | Perform a raw lookup with per-call 'QueryControls' overrides,
-- returning the full 'DNSMessage' or a 'DNSError'.  The supplied
-- controls are merged into the resolver's ambient query controls:
-- only the flag and EDNS bits specified in the controls affect the
-- outgoing query, the rest are inherited from the resolver
-- configuration.  Use 'lookupAnswers' (or the per-RRtype 'Lookup'
-- functions) when you want only the answer RRs for the requested
-- name and type, rather than the entire response 'DNSMessage'.
--
lookupRawCtl :: Resolver -> QueryControls -> Domain -> RRCLASS
             -> RRTYPE -> IO (Either DNSError DNSMessage)
lookupRawCtl rslv ctls dom qclass qtype =
    runDNSIO (lookupRawCtl_ rslv ctls dom qclass qtype)

-- | Find the RRs that answer the query, following any CNAMEs
-- found when there's no exact match for the qname and qtype.
-- Also returns any associated covering DNSSEC RRSIGs.
filterRelevant :: [RR] -> RRCLASS -> RRTYPE -> Domain -> [RR]
filterRelevant rrs qclass qtype =
    [ rr | rr <- rrs
    , rrClass rr == qclass
    , rrType rr == qtype || rrType rr == CNAME ]
    & rrSetsFromList
    & map (\s -> ((rrSetType s, rrSetOwner s), rrSetRecs s))
    & M.fromList
    & loop
  where
    -- Cycles are avoided by deleting traversed CNAMEs.
    loop :: Map (RRTYPE, Domain) [RR] -> Domain -> [RR]
    loop sm (canonicalise -> qname)
          | Just found <- M.lookup (qtype, qname) sm = found
          | (Just found, sm') <- M.alterF (, Just []) (CNAME, qname) sm
          , [t] <- [t | T_CNAME t <- monoRData $ map rrData found] = loop sm' t
          | otherwise = []

-------

-- | Perform the requested query and return the answer RRs from the
-- response, or a 'DNSError' carrying the RCODE for error responses.
-- The 'QueryControls' argument carries per-call tweaks; it is
-- merged onto the resolver's ambient query controls, so callers only
-- need to specify the flag and EDNS bits they want to change, the
-- rest are inherited from the resolver configuration.
--
-- Note that @NXDOMAIN@ is /not/ a lookup error.  An empty list of
-- RRs is returned for both @NODATA@ and @NXDOMAIN@.
--
-- If the nameserver's response does not include any RRs matching
-- query name and type, but does include a @CNAME@ record for the
-- requested name, the response is (recursively) rescanned for
-- records matching that name and type instead.  Note, no
-- additional queries are issued if the final CNAME found does
-- not lead to any record of the desired record type.
--
-- The returned RRs may include covering @DNSSEC@ signatures when the
-- 'Net.DNSBase.Flags.DOflag' is set as part of the 'QueryControls', and
-- the response was signed.
--
-- The presence of @RRSIG@ records does not however imply that the
-- response was /validated/ by the resolver.  For that one would
-- typically use a trusted DNSSEC-validating local (loopback)
-- resolver, to which the network path is immune to potential
-- active attacks, and inspect the 'Net.DNSBase.Flags.ADflag' in
-- the response message.
--
-- The full response 'DNSMessage' can be obtained via 'lookupRawCtl'.
--
lookupAnswers :: Resolver -> QueryControls -> RRCLASS -> RRTYPE -> Domain
              -> IO (Either DNSError [RR])
lookupAnswers rslv ctls cls typ dom = runDNSIO do
    msg <- lookupRawCtl_ rslv ctls dom cls typ
    extractAnswers_ msg

-- | Given a 'DNSMessage' return answer RRs that match its question,
-- possibly after /chasing/ @CNAME@ aliases within the answer
-- section of the message.
extractAnswers :: DNSMessage -> IO (Either DNSError [RR])
extractAnswers msg = runDNSIO (extractAnswers_ msg)

-- | Extract the answer RRs matching the question from a 'DNSMessage'
-- when the RCODE is non-error.
extractAnswers_ :: Monad m => DNSMessage -> ExceptT DNSError m [RR]
extractAnswers_ m@(dnsMsgQu -> [q])
    | NOERROR  <- dnsMsgRC m = pure $ filterRelevant (dnsMsgAn m) cls typ dom
    | NXDOMAIN <- dnsMsgRC m = pure []
    | YXDOMAIN <- dnsMsgRC m = pure []
    | otherwise              = throwE $ ResponseError $ dnsMsgRC m
  where
    dom = dnsTripleName q
    cls = dnsTripleClass q
    typ = dnsTripleType q
extractAnswers_ m =
    throwE $ UserError $ BadResponseQuestionCount $ length $ dnsMsgQu m


-- | @IPv4@ addresses of query domain.
lookupA     :: Lookup IPv4
lookupA = lookupX A $ \(T_A ip) -> ip

-- | @IPv6@ addresses of query domain.
lookupAAAA  :: Lookup IPv6
lookupAAAA = lookupX AAAA $ \(T_AAAA ip) -> ip

-- | @CNAME@s of query domain (should be at most one).
lookupCNAME :: Lookup Domain
lookupCNAME = lookupX CNAME $ \(T_CNAME dom) -> dom

-- | @CAA@s @RData@ of query domain
lookupCAA :: Lookup T_caa
lookupCAA = lookupX CAA id

-- | @DNAME@s of query domain (should be at most one).
lookupDNAME :: Lookup Domain
lookupDNAME = lookupX DNAME $ \(T_DNAME dom) -> dom

-- | @PTR@ names of query domain.
lookupPTR   :: Lookup Domain
lookupPTR = lookupX PTR $ \(T_PTR dom) -> dom

-- | Nameservers of query domain.
lookupNS :: Lookup Domain
lookupNS = lookupX NS $ \(T_NS dom) -> dom

-- | @NULL@ RR payload of query domain.
lookupNULL  :: Lookup ShortByteString
lookupNULL = lookupX NULL $ \ (T_NULL b16) -> getShort16 b16

-- | @AFSDB@ RData of query domain.
lookupAFSDB  :: Lookup T_afsdb
lookupAFSDB = lookupX AFSDB id

-- | @CDNSKEY@ RData of query domain.
lookupCDNSKEY  :: Lookup T_cdnskey
lookupCDNSKEY = lookupX CDNSKEY id

-- | @CDS@ RData of query domain.
lookupCDS  :: Lookup T_cds
lookupCDS = lookupX CDS id

-- | @DNSKEY@ RData of query domain.
lookupDNSKEY  :: Lookup T_dnskey
lookupDNSKEY = lookupX DNSKEY id

-- | @DS@ RData of query domain.
lookupDS  :: Lookup T_ds
lookupDS = lookupX DS id

-- | @HINFO@ RData of query domain.
lookupHINFO  :: Lookup T_hinfo
lookupHINFO = lookupX HINFO id

-- | @HTTPS@ RData of query domain.
lookupHTTPS  :: Lookup T_https
lookupHTTPS = lookupX HTTPS id

-- | @MX@ RData of query domain.
lookupMX  :: Lookup T_mx
lookupMX = lookupX MX id

-- | @NSEC@ RData of query domain.
lookupNSEC  :: Lookup T_nsec
lookupNSEC = lookupX NSEC id

-- | @NSEC3PARAM@ RData of query domain.
lookupNSEC3PARAM  :: Lookup T_nsec3param
lookupNSEC3PARAM = lookupX NSEC3PARAM id

-- | @SOA@ RData of query domain.
lookupSOA  :: Lookup T_soa
lookupSOA = lookupX SOA id

-- | @RP@ RData of query domain.
lookupRP :: Lookup T_rp
lookupRP = lookupX RP id

-- | @SRV@ RData of query domain.
lookupSRV  :: Lookup T_srv
lookupSRV = lookupX SRV id

-- | @SSHFP@ RData of query domain.
lookupSSHFP  :: Lookup T_sshfp
lookupSSHFP = lookupX SSHFP id

-- | @SVCB@ RData of query domain.
lookupSVCB  :: Lookup T_svcb
lookupSVCB = lookupX SVCB id

-- | @TLSA@ RData of query domain.
lookupTLSA  :: Lookup T_tlsa
lookupTLSA = lookupX TLSA id

-- | @TXT@ RData of query domain.  Applications typically concatenate each list
-- of character strings into a single combined value.
lookupTXT  :: Lookup (NonEmpty ShortByteString)
lookupTXT = lookupX TXT \(T_TXT chunks) -> chunks

-- | @ZONEMD@ RData of query domain.
lookupZONEMD  :: Lookup T_zonemd
lookupZONEMD = lookupX ZONEMD id
