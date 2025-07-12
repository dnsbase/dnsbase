{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.Lookup
    ( Lookup
    , extractAnswers
    , lookupRawCtl
    , lookupRaw
    , lookupAnswers
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
    , lookupNULL
    , lookupPTR
    , lookupRP
    , lookupSOA
    , lookupSRV
    , lookupSVCB
    , lookupTLSA
    , lookupTXT
    ) where

import qualified Data.Map.Strict as M
import Data.Foldable (toList)

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
import Net.DNSBase.RRTYPE

-- | Simple lookup type signature
type Lookup a = Resolver -> Domain -> DNSIO [a]

-- | Generic Answer RData-only lookup, applying a function to each result.
lookupX :: KnownRData a => RRTYPE -> (a -> b) -> Lookup b
lookupX typ f rslv = getOnly <.> lookupAnswers rslv mempty IN typ
  where
    getOnly = mapMaybe (f <.> rrDataCast)

-- Perform a query with default resolver controls.
lookupRaw :: Resolver -> Domain -> RRCLASS -> RRTYPE -> DNSIO DNSMessage
lookupRaw rslv = lookupRawCtl rslv mempty

-- | Find the RRset that answers the query, following any CNAMEs found when
-- there's no exact match for the qname and qtype.  Also returns any associated
-- covering DNSSEC RRSIGs.
filterRelevant :: [RR] -> RRCLASS -> RRTYPE -> Domain -> [RR]
filterRelevant rrs qclass qtype = reverse . loop rrsets
  where
    rrKey = (,) <$> canonicalise . rrOwner <*> groupType
    rrKeyValue = (,) <$> rrKey <*> (: [])
    sameClass = filter ((== qclass) . rrClass) rrs
    rrsets = M.fromListWith (++) $ map rrKeyValue sameClass

    groupType :: RR -> RRTYPE
    groupType rr = case rrDataCast rr of
        Just rd@(T_RRSIG {}) -> sigType rd
        _                    -> rrType rr

    -- Cycles are avoided by deleting traversed CNAMEs.
    loop m (canonicalise -> qname)
          | Just found <- M.lookup (qname, qtype) rrsets
            = found
          | (Just rrset, m') <- M.alterF (, Nothing) (qname, CNAME) m
          , [t] <- [ t | rr <- rrset, T_CNAME t <- toList $ rrDataCast rr ]
            = loop m' t
          | otherwise
            = []

-------

-- | Performs the requested query, returning the answer /RRset/ from the
-- response provided it was not an error.  Otherwise, throws a 'DNSError'
-- encapsulating the RCODE.
--
-- Note that @NXDOMAIN@ is a not a lookup /error/, an empty /RRset/ is returned
-- both for @NODATA@ and @NXDOMAIN@.
--
-- The returned RRset may include covering @DNSSEC@ signatures when the
-- 'DOflag' is set as part of the 'QueryControls', and the response was signed.
-- This does not however necessarily mean that the response was /validated/ by
-- the resolver.  For that one would typically use a trusted DNSSEC-validating
-- local (loopback) resolver, to which the network path is immune to potential
-- active attacks, and inspect the 'ADflag' in the response message.
--
-- The full response 'DNSMessage' can be obtained via 'lookupRawCtl'.
--
lookupAnswers :: Resolver -> QueryControls -> RRCLASS -> RRTYPE -> Domain -> DNSIO [RR]
lookupAnswers rslv ctls cls typ dom =
    lookupRawCtl rslv ctls dom cls typ >>= extractAnswers


-- | Extract the answer /RRset/ matching the 'Question' from a 'DNSMessage'
-- provided the response code was not an error.  Otherwise, throws a 'DNSError'
-- encapsulating the @RCODE@.
--
-- Note that @NXDOMAIN@ is a not a lookup /error/, an empty /RRset/ is returned
-- both for @NODATA@ and @NXDOMAIN@.
--
-- The returned RRset may include covering @DNSSEC@ signatures when the
-- 'DOflag' is set as part of the 'QueryControls', and the response was signed.
-- This does not however necessarily mean that the response was /validated/ by
-- the resolver.  For that one would typically use a trusted DNSSEC-validating
-- local (loopback) resolver, to which the network path is immune to potential
-- active attacks, and inspect the 'ADflag' in the response message.
--
extractAnswers :: Monad m => DNSMessage -> ExceptT DNSError m [RR]
extractAnswers m@(dnsMsgQu -> [q])
    | NOERROR  <- dnsMsgRC m = pure $ filterRelevant (dnsMsgAn m) cls typ dom
    | NXDOMAIN <- dnsMsgRC m = pure []
    | YXDOMAIN <- dnsMsgRC m = pure []
    | otherwise              = throwE $ ResponseError $ dnsMsgRC m
  where
    dom = dnsTripleName q
    cls = dnsTripleClass q
    typ = dnsTripleType q
extractAnswers m =
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

-- | @SOA@ RData of query domain.
lookupSOA  :: Lookup T_soa
lookupSOA = lookupX SOA id

-- | @RP@ RData of query domain.
lookupRP :: Lookup T_rp
lookupRP = lookupX RP id

-- | @SRV@ RData of query domain.
lookupSRV  :: Lookup T_srv
lookupSRV = lookupX SRV id

-- | @SVCB@ RData of query domain.
lookupSVCB  :: Lookup T_svcb
lookupSVCB = lookupX SVCB id

-- | @TLSA@ RData of query domain.
lookupTLSA  :: Lookup T_tlsa
lookupTLSA = lookupX TLSA id

-- | @TXT@ RData of query domain.  Applications typically concatenate the list
-- of character strings into a single combined value.
lookupTXT  :: Lookup T_txt
lookupTXT = lookupX TXT id
