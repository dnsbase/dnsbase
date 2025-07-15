{-# LANGUAGE RecordWildCards #-}

module Net.DNSBase.RData.CSYNC
    ( -- * CSYNC RData
      T_csync(..)
    , NsecTypes
    , nsecTypesFromList
    , nsecTypesToList
    , hasRRtype
    ) where

import Net.DNSBase.Internal.Util

import Net.DNSBase.Decode.State
import Net.DNSBase.Encode.State
import Net.DNSBase.NsecTypes
import Net.DNSBase.Present
import Net.DNSBase.RData
import Net.DNSBase.RRTYPE

-----------------

-- | [CSYNC RDATA](https://www.rfc-editor.org/rfc/rfc7477.html#section-2.1.1)
-- Used in child-to-parent signalling.
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                          SOA Serial                           |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |       Flags                   |            Type Bit Map       /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > /                     Type Bit Map (continued)                  /
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
--
data T_csync = T_CSYNC
    { csyncSerial :: Word32    -- ^ Zone serial number
    , csyncFlags  :: Word16    -- ^ flag Bits
    , csyncTypes  :: NsecTypes -- ^ Type Bitmap
    } deriving (Eq, Show)

instance Ord T_csync where
    a `compare` b = csyncSerial a `compare` csyncSerial b
                 <> csyncFlags  a `compare` csyncFlags  b
                 <> csyncTypes  a `compare` csyncTypes  b

instance Presentable T_csync where
    present T_CSYNC{..} =
        present          csyncSerial
        . presentSp      csyncFlags
        . presentSpTypes csyncTypes

instance KnownRData T_csync where
    rdType _ = CSYNC
    {-# INLINE rdType #-}
    rdEncode T_CSYNC{..} = do
        putSizedBuilder $
           mbWord32 csyncSerial
           <> mbWord16 csyncFlags
        putNsecTypes csyncTypes
    rdDecode _ _ len = do
        csyncSerial <- get32
        csyncFlags  <- get16
        csyncTypes <- getNsecTypes (len - 6)
        pure $ RData T_CSYNC{..}
