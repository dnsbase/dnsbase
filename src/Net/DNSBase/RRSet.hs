{-# LANGUAGE RecordWildCards #-}
module Net.DNSBase.RRSet
    ( RRSet(..)
    , rrSetsFromList
    )
    where
import qualified Data.List as L
import qualified Data.List.NonEmpty as NE

import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.RR
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.RRCLASS
import Net.DNSBase.Internal.Util
import Net.DNSBase.RData.Dnssec

data RRSet = RRSet
    { rrSetOwner :: Domain
    , rrSetClass :: RRCLASS
    , rrSetType  :: RRTYPE
    , rrSetRecs  :: [RR]
    , rrSetSigs  :: [RR]
    }

rrSetsFromList :: [RR] -> [RRSet]
rrSetsFromList rrs = rrs
    & map decorate
    & L.sortBy (comparing drrKey)
    & NE.groupWith drrKey
    & makeSets
  where
    decorate :: RR -> (RR, RRTYPE, Domain)
    decorate rr =
        let !styp = maybe (rrType rr) (sigType @N_rrsig) (rrDataCast rr)
            !host = canonicalise (rrOwner rr)
         in (rr, styp, host)

    drrKey :: (RR, RRTYPE, Domain) -> (RRTYPE, RRCLASS, Domain)
    drrKey (rr, typ, host) = (typ, rrClass rr, host)

    makeSets :: [NonEmpty (RR, RRTYPE, Domain)] -> [RRSet]
    makeSets [] = []
    makeSets (((rr@(rrClass -> rrSetClass), rrSetType, rrSetOwner) :| rest) : grps)
        | !owner <- rrOwner rr
        , (rrSetRecs, rrSetSigs) <- L.partition ((== rrSetType) . rrType)
            $ rr : rrsOfWithOwner owner rest
        , not (null rrSetRecs) = RRSet {..} : makeSets grps
        | otherwise = makeSets grps

    rrsOfWithOwner owner = foldr go []
      where
        go (setOwner -> !h) !t = h : t
        setOwner (r, _, _) = r {rrOwner = owner}
