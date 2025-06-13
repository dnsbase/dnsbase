{-# LANGUAGE RecordWildCards #-}
module Net.DNSBase.Decode.Internal.Message
      ( getMessage
      ) where

import Data.List (partition)

import Net.DNSBase.Decode.Internal.Domain
import Net.DNSBase.Decode.Internal.Option
import Net.DNSBase.Decode.Internal.RData
import Net.DNSBase.Decode.Internal.State
import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.EDNS
import Net.DNSBase.Internal.Error
import Net.DNSBase.Internal.Flags
import Net.DNSBase.Internal.Message
import Net.DNSBase.Internal.Opcode
import Net.DNSBase.Internal.RCODE
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.RR
import Net.DNSBase.Internal.RRCLASS
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.Util

-- | Decoder for a complete DNSMessage, including EDNS pseudo-header information when present
getMessage :: RDataMap -> OptionMap -> SGet DNSMessage
getMessage dm om = local (setDecodeSection DnsHeaderSection) do
    phd <- getPartialHeader
    qdCount <- getInt16
    anCount <- getInt16
    nsCount <- getInt16
    arCount <- getInt16
    queries <- local (setDecodeSection DnsQuestionSection) $ getQueries qdCount
    if | hasAnyFlags TCflag $ p_dnsMsgFl phd
            -- Don't bother parsing RRs of truncated messages, we won't use
            -- them, and they can be truncated in a way that raises parser
            -- errors.
         -> pure $ mkMsg phd No queries [] [] []
       | otherwise -> do
            if | q:_ <- queries -> () <$ setLastOwner (dnsTripleName q)
               | otherwise      -> pure ()
            answers <- local (setDecodeSection DnsAnswerSection) $ getRRs dm Nothing anCount
            authrrs <- local (setDecodeSection DnsAuthoritySection) $ getRRs dm Nothing nsCount
            addnrrs <- local (setDecodeSection DnsAdditionalSection) $ getRRs dm (Just om) arCount
            case partition isOpt addnrrs of
                ([], rrs) -> pure $ mkMsg phd No queries answers authrrs rrs
                ([optrr], rrs)
                    | RootDomain <- rrOwner optrr
                    , edns <- getEDNS optrr
                      -> pure $ mkMsg phd edns queries answers authrrs rrs
                _ -> local (setDecodeSection DnsEDNSSection) $
                         failSGet "Multiple or bad additional section OPT records"
  where
    isOpt :: RR -> Bool
    isOpt = (== OPT) . rdataType . rrData

    getEDNS :: RR -> EDNSData
    getEDNS rr
      | Just (edns, ext_rc, ext_fl) <- optEDNS rr = Yes{..}
        -- Should not happen, the OPT record should always be a T_OPT!
      | otherwise                                 = No

    optEDNS :: RR -> Maybe (EDNS, Word8, Word16)
    optEDNS (RR _ vcl vttl rd)
        | Just (T_OPT opts) <- fromRData rd
        , ext_rc <- fromIntegral $ (vttl `shiftR` 24) .&. 0xff
        , vers   <- fromIntegral $ (vttl `shiftR` 16) .&. 0xff
        , ext_fl <- fromIntegral $ vttl .&. 0xffff
            = Just (EDNS vers (coerce vcl) opts, ext_rc, ext_fl)
        | otherwise
            = Nothing

-- | Decoder for a list of 'Question' (query) fields appearing within a DNS
-- message.  The integer parameter corresponds to the reported QDCOUNT of the
-- message, which should never be more than 1; this decoder neither tests nor
-- enforces this constraint and will attempt to decode exactly as many
-- questions as are reported to exist.
getQueries :: Int -> SGet [Question]
getQueries n = replicateM n getQuery
  where
    getQuery :: SGet Question
    getQuery = DnsTriple <$> getDomain <*> getType <*> getClass
      where
        getType = RRTYPE <$> get16
        getClass = RRCLASS <$> get16

-- | Decoder for a known-length list of resource records
getRRs :: RDataMap -> Maybe OptionMap -> Int -> SGet [RR]
getRRs dm om n = replicateM n (getRR dm om)

-- | Decoder for a 'PartialHeader' contained in the header of a DNS message
getPartialHeader :: SGet PartialHeader
getPartialHeader =
    makeHeader <$> decodeMsgId <*> getOpRFlags
  where
    makeHeader mid (oc,rc,fl) = PartialHeader mid oc rc fl
    decodeMsgId = get16

    getOpRFlags :: SGet (Opcode, PartialRCODE, PartialDNSFlags)
    getOpRFlags = do
        raw <- get16
        return $ ( extractOpcode raw
                 , extractRCODE  raw
                 , makeDNSFlags  raw
                 )


type PartialRCODE = RCODE
type PartialDNSFlags = DNSFlags


-- | Data type representing the absence or presence of
-- an OPT record, which individually represents the extended bits of
-- the DNS flags and RCODE contained in the EDNS pseudo-header
-- and the remaining EDNS data
data EDNSData = No
              | Yes { ext_fl :: Word16
                    , ext_rc :: Word8
                    , edns   :: EDNS
                    } deriving (Eq)

-- | Component of DNS message header that is extracted directly from
-- leading bytes of the DNS message (i.e. without parsing EDNS pseudo-header)
data PartialHeader = PartialHeader {
      p_dnsMsgId :: QueryID
    , p_dnsMsgOp :: Opcode
    , p_dnsMsgRC :: PartialRCODE
    , p_dnsMsgFl :: PartialDNSFlags
    } deriving (Eq, Show)

-- | Completes a 'PartialHeader' with a (possibly vacuous) 'EDNSData' to form a 'DNSHeader'
mkMsg :: PartialHeader
      -> EDNSData
      -> [Question]
      -> [RR] -> [RR] -> [RR]
      -> DNSMessage
mkMsg PartialHeader{..} No dnsMsgQu dnsMsgAn dnsMsgNs dnsMsgAr =
    DNSMessage {..}
  where
    dnsMsgId = p_dnsMsgId
    dnsMsgOp = p_dnsMsgOp
    dnsMsgRC = p_dnsMsgRC
    dnsMsgFl = p_dnsMsgFl
    dnsMsgEx = Nothing

mkMsg PartialHeader{..} Yes{..} dnsMsgQu dnsMsgAn dnsMsgNs dnsMsgAr =
    DNSMessage {..}
  where
    dnsMsgId = p_dnsMsgId
    dnsMsgOp = p_dnsMsgOp
    dnsMsgRC = extendRCODE p_dnsMsgRC ext_rc
    dnsMsgFl = extendFlags p_dnsMsgFl ext_fl
    dnsMsgEx = Just edns
