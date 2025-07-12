{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.Internal.Message
    ( DNSMessage(..)
    , Question
    , QueryID
    , putMessage
    , putRequest
    )
    where

import Net.DNSBase.EDNS.Internal.Option
import Net.DNSBase.Encode.Internal.State
import Net.DNSBase.Internal.Domain
import Net.DNSBase.Internal.Flags
import Net.DNSBase.Internal.Opcode
import Net.DNSBase.Internal.RCODE
import Net.DNSBase.Internal.RData
import Net.DNSBase.Internal.RRTYPE
import Net.DNSBase.Internal.EDNS
import Net.DNSBase.Internal.RRCLASS
import Net.DNSBase.Internal.RR
import Net.DNSBase.Internal.Util

-- | DNS over UDP uses 16-bit query ids to better correlate questions and
-- answers and to (inadequately) reduce the risk of cache-poisoning through
-- forged response packets.  They are still used with TCP to keep the header
-- format the same.
type QueryID = Word16

----------------------------------------------------------------

-- | DNS query or response header, here consisting of just the query ID and
-- the flags, sans the record counts, which are implicit in the corresponding
-- lists, [RFC1035 4.1.1](https://tools.ietf.org/html/rfc1035#section-4.1.1),
-- updated by [RFC2535](https://tools.ietf.org/html/rfc2535#section-6.1).
--
-- The basic DNS header contains the following fields:
--
-- >                                 1  1  1  1  1  1
-- >   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                      ID                       |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                    QDCOUNT                    |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                    ANCOUNT                    |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                    NSCOUNT                    |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                    ARCOUNT                    |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
-- The basic 4-bit 'RCODE' is augmented with 8 bits from the EDNS header,
-- forming a single /extended/ 12-bit RCODE, with the basic @RCODE@ as its
-- least-significant 4 bits.  Similarly, the /extended/ 32-bit 'DNSFlags' are
-- a combination of the basic flags above with 16 more flag bits from the
-- EDNS header, with the basic flags in the low 16-bits (with the @Opcode@
-- and @RCODE@ bits always cleared).
--

-- | DNS message format for queries and replies,
-- [RFC1035 4.1](https://tools.ietf.org/html/rfc1035#section-4.1)
--
-- >  +---------------------+
-- >  |        Header       |
-- >  +---------------------+
-- >  |       Question      | the question for the name server
-- >  +---------------------+
-- >  |        Answer       | RRs answering the question
-- >  +---------------------+
-- >  |      Authority      | RRs pointing toward an authority
-- >  +---------------------+
-- >  |      Additional     | RRs holding additional information
-- >  +---------------------+
--
data DNSMessage = DNSMessage
    { dnsMsgId :: QueryID       -- ^ Query or reply identifier.
    , dnsMsgOp :: Opcode        -- ^ The requested operation
    , dnsMsgRC :: RCODE         -- ^ The (extended) result code
    , dnsMsgFl :: DNSFlags      -- ^ The (extended) flags
    , dnsMsgEx :: Maybe EDNS    -- ^ EDNS pseudo-header
    , dnsMsgQu :: [DnsTriple]   -- ^ The question name, type, class
    , dnsMsgAn :: [RR]          -- ^ Answers
    , dnsMsgNs :: [RR]          -- ^ Authority records
    , dnsMsgAr :: [RR]          -- ^ Additional records
    } deriving (Eq, Show)

-- | DNS Question, [RFC1035 4.1.2](https://tools.ietf.org/html/rfc1035#section-4.1.2)
--
-- >                                 1  1  1  1  1  1
-- >   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                                               |
-- > /                     QNAME                     /
-- > /                                               /
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                     QTYPE                     |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
-- > |                     QCLASS                    |
-- > +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
--
type Question = DnsTriple

putQuestion :: Question -> SPut s RData
putQuestion DnsTriple{..} = do
    putDomain dnsTripleName
    put32 $ fromIntegral @Word16 (coerce dnsTripleType) `unsafeShiftL` 16 .|.
            fromIntegral @Word16 (coerce dnsTripleClass)

----------------------------------------------------------------

putRequest :: QueryID -> DNSFlags -> Maybe EDNS -> Question -> SPut s RData
putRequest qid flags (Just EDNS{..}) question = do
    -- header
    put64 $ fromIntegral qid `unsafeShiftL` 48 .|.
            fromIntegral (basicFlags Query NOERROR flags) `unsafeShiftL` 32 .|.
            -- RR counts
            0x0001_0000
    put32 $ 0x0000_0001
    --
    putQuestion question
    -- OPT pseudo-RR
    put8 0  -- Root Domain
    put64 $ fromIntegral @Word16 (coerce OPT) `unsafeShiftL` 48 .|.
            fromIntegral ednsUdpSize `unsafeShiftL` 32 .|.
            fromIntegral ednsVersion `unsafeShiftL` 16 .|.
            fromIntegral (extendedFlags flags)
    if (null ednsOptions)
    then put16 0
    else passLen $ mapM_ putOption ednsOptions
putRequest qid flags _ question = do
    let ef = extendedFlags flags
    when (ef /= 0) $ failWith $ const EDNSRequired
    -- header
    put64 $ fromIntegral qid `unsafeShiftL` 48 .|.
            fromIntegral (basicFlags Query NOERROR flags) `unsafeShiftL` 32 .|.
            -- RR counts
            0x0001_0000
    put32 $ 0x0000_0000
    --
    putQuestion question

putMessage :: DNSMessage -> SPut s RData
putMessage DNSMessage{..}
    | Just EDNS{..} <- dnsMsgEx
      = do
        -- header
        put64 $ msgid `unsafeShiftL` 48 .|.
                flags `unsafeShiftL` 32 .|.
                -- RR counts
                qdcount `unsafeShiftL` 16 .|.
                ancount
        put32 $ nscount `unsafeShiftL` 16 .|.
                arcount
        --
        mapM_ putQuestion dnsMsgQu
        mapM_ putRR dnsMsgAn
        mapM_ putRR dnsMsgNs
        -- OPT pseudo-RR
        put8 0  -- Root Domain
        put32 $ fromIntegral @Word16 (coerce OPT) `unsafeShiftL` 16 .|.
                fromIntegral ednsUdpSize
        put32 $ (fromIntegral rc .&. 0xff0) `unsafeShiftL` 20 .|.
                fromIntegral ednsVersion `unsafeShiftL` 16 .|.
                fromIntegral (extendedFlags dnsMsgFl)
        if (null ednsOptions)
        then put16 0
        else passLen $ mapM_ putOption ednsOptions
        -- Remaining additional records
        mapM_ putRR dnsMsgAr
    | otherwise
      = do
        let ef = extendedFlags dnsMsgFl
        when (rc > 0xf || ef /= 0) $ failWith $ const EDNSRequired
        -- header
        put64 $ msgid `unsafeShiftL` 48 .|.
                flags `unsafeShiftL` 32 .|.
                -- RR counts
                qdcount `unsafeShiftL` 16 .|.
                ancount
        put32 $ nscount `unsafeShiftL` 16 .|.
                arcount
        --
        mapM_ putQuestion dnsMsgQu
        mapM_ putRR dnsMsgAn
        mapM_ putRR dnsMsgNs
        mapM_ putRR dnsMsgAr
  where
    msgid   = fromIntegral dnsMsgId
    qdcount = fromIntegral $ length dnsMsgQu
    ancount = fromIntegral $ length dnsMsgAn
    nscount = fromIntegral $ length dnsMsgNs
    arcount = fromIntegral $ length dnsMsgAr + 1
    flags   = fromIntegral $ basicFlags dnsMsgOp dnsMsgRC dnsMsgFl
    (RCODE rc) = dnsMsgRC
