module Net.DNSBase.Secalgs
    ( DNSKEYAlg
        ( ..
        , KA_RSAMD5
        , KA_DH
        , KA_DSA
        , KA_RSASHA1
        , KA_DSA_NSEC3_SHA1
        , KA_RSASHA1_NSEC3_SHA1
        , KA_RSASHA256
        , KA_RSASHA512
        , KA_ECC_GOST
        , KA_ECDSAP256SHA256
        , KA_ECDSAP384SHA384
        , KA_ED25519
        , KA_ED448
        )
    , DSHashAlg
        ( ..
        , DS_SHA1
        , DS_SHA256
        , DS_GOST94
        , DS_SHA384
        )
    , NSEC3HashAlg
        ( ..
        , N3_SHA1
        )
    -- | [TLSA Certificate Usages](https://tools.ietf.org/html/rfc7218#section-2.1)
    , DaneUsage
        ( ..
        , PKIX_TA
        , PKIX_EE
        , DANE_TA
        , DANE_EE
        , PrivCert
        )
    -- | [TLSA Selectors](https://tools.ietf.org/html/rfc7218#section-2.2)
    , DaneSelector
        ( ..
        , Cert -- ^ Note: as distinct from the @'CERT'@ @'RRTYPE'@.
        , SPKI
        , PrivSel
        )
    -- | [TLSA Matching Types](https://tools.ietf.org/html/rfc7218#section-2.3)
    , DaneMtype
        ( ..
        , SHA2_256
        , SHA2_512
        , Full
        , PrivMatch
        )
    , SshKeyAlgorithm
        ( SSHKEYRSA
        , SSHKEYDSA
        , SSHKEYECDSA
        , SSHKEYED25519
        , SSHKEYED448
        )
    , SshHashType
        ( SSHSHA2_256
        , SSHSHA2_512
        )
    ) where

import Net.DNSBase.Internal.Present
import Net.DNSBase.Internal.Util


-- | DNSKEY algorithm, displayed as a number
newtype DNSKEYAlg = DNSKEYAlg Word8
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

instance Presentable DNSKEYAlg where
    present (DNSKEYAlg ka) = present ka
    {-# INLINE present #-}

-- | DS Hash algorithm, displayed as a number
newtype DSHashAlg = DSHashAlg Word8
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

instance Presentable DSHashAlg where
    present (DSHashAlg ha) = present ha
    {-# INLINE present #-}

-- | NSEC3 Hash algorithm, displayed as a number
newtype NSEC3HashAlg = NSEC3HashAlg Word8
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

instance Presentable NSEC3HashAlg where
    present (NSEC3HashAlg na) = present na
    {-# INLINE present #-}

-- | TLSA certificate usages, displayed as a number
newtype DaneUsage = DaneUsage Word8
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

instance Presentable DaneUsage where
    present (DaneUsage u) = present u
    {-# INLINE present #-}

-- | TLSA selectors, displayed as a number
newtype DaneSelector = DaneSelector Word8
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

instance Presentable DaneSelector where
    present (DaneSelector s) = present s
    {-# INLINE present #-}

-- | TLSA matching types, displayed as a number
newtype DaneMtype = DaneMtype Word8
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

instance Presentable DaneMtype where
    present (DaneMtype m) = present m
    {-# INLINE present #-}

-- | SSH host key algorithms
newtype SshKeyAlgorithm = SshKeyAlgorithm Word8
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

instance Presentable SshKeyAlgorithm where
    present SSHKEYRSA           = present @String "RSA"
    present SSHKEYDSA           = present @String "DSA"
    present SSHKEYECDSA         = present @String "ECDSA"
    present SSHKEYED25519       = present @String "Ed25519"
    present SSHKEYED448         = present @String "Ed448"
    present (SshKeyAlgorithm n) = present @String "SSHKEYTYPE" . present n

-- | SSH hash type
newtype SshHashType = SshHashType Word8
    deriving newtype (Eq, Ord, Enum, Bounded, Num, Real, Integral, Show, Read)

instance Presentable SshHashType where
    present SSHSHA2_256     = present @String "SHA256"
    present SSHSHA2_512     = present @String "SHA512"
    present (SshHashType n) = present @String "SSHHashTYPE" . present n

-- DNSKEY algorithms

pattern KA_RSAMD5 :: DNSKEYAlg
pattern KA_RSAMD5  = DNSKEYAlg 1

pattern KA_DH :: DNSKEYAlg
pattern KA_DH  = DNSKEYAlg 2

pattern KA_DSA :: DNSKEYAlg
pattern KA_DSA  = DNSKEYAlg 3

pattern KA_RSASHA1 :: DNSKEYAlg
pattern KA_RSASHA1  = DNSKEYAlg 5

pattern KA_DSA_NSEC3_SHA1 :: DNSKEYAlg
pattern KA_DSA_NSEC3_SHA1  = DNSKEYAlg 6

pattern KA_RSASHA1_NSEC3_SHA1 :: DNSKEYAlg
pattern KA_RSASHA1_NSEC3_SHA1  = DNSKEYAlg 7

pattern KA_RSASHA256 :: DNSKEYAlg
pattern KA_RSASHA256  = DNSKEYAlg 8

pattern KA_RSASHA512 :: DNSKEYAlg
pattern KA_RSASHA512  = DNSKEYAlg 10

pattern KA_ECC_GOST :: DNSKEYAlg
pattern KA_ECC_GOST  = DNSKEYAlg 12

pattern KA_ECDSAP256SHA256 :: DNSKEYAlg
pattern KA_ECDSAP256SHA256  = DNSKEYAlg 13

pattern KA_ECDSAP384SHA384 :: DNSKEYAlg
pattern KA_ECDSAP384SHA384  = DNSKEYAlg 14

pattern KA_ED25519 :: DNSKEYAlg
pattern KA_ED25519  = DNSKEYAlg 15

pattern KA_ED448 :: DNSKEYAlg
pattern KA_ED448  = DNSKEYAlg 16

-- DS digest type algorithms

pattern DS_SHA1 :: DSHashAlg
pattern DS_SHA1  = DSHashAlg 1

pattern DS_SHA256 :: DSHashAlg
pattern DS_SHA256  = DSHashAlg 2

pattern DS_GOST94 :: DSHashAlg
pattern DS_GOST94  = DSHashAlg 3

pattern DS_SHA384 :: DSHashAlg
pattern DS_SHA384  = DSHashAlg 4

-- NSEC3 Hash algorithms

pattern N3_SHA1 :: NSEC3HashAlg
pattern N3_SHA1  = NSEC3HashAlg 1

-- DANE TLSA certificate usages

pattern PKIX_TA :: DaneUsage
pattern PKIX_TA  = DaneUsage 0

pattern PKIX_EE :: DaneUsage
pattern PKIX_EE  = DaneUsage 1

pattern DANE_TA :: DaneUsage
pattern DANE_TA  = DaneUsage 2

pattern DANE_EE :: DaneUsage
pattern DANE_EE  = DaneUsage 3

pattern PrivCert :: DaneUsage
pattern PrivCert  = DaneUsage 255

-- DANE TLSA selectors

pattern Cert :: DaneSelector
pattern Cert  = DaneSelector 0

pattern SPKI :: DaneSelector
pattern SPKI  = DaneSelector 1

pattern PrivSel :: DaneSelector
pattern PrivSel  = DaneSelector 255

-- DANE TLSA matching types

pattern Full :: DaneMtype
pattern Full  = DaneMtype 0

pattern SHA2_256 :: DaneMtype
pattern SHA2_256  = DaneMtype 1

pattern SHA2_512 :: DaneMtype
pattern SHA2_512  = DaneMtype 2

pattern PrivMatch :: DaneMtype
pattern PrivMatch  = DaneMtype 255

-- [SSHFP KEY algorithms](https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml)

pattern SSHKEYRSA     :: SshKeyAlgorithm;       pattern SSHKEYRSA     = 1
pattern SSHKEYDSA     :: SshKeyAlgorithm;       pattern SSHKEYDSA     = 2
pattern SSHKEYECDSA   :: SshKeyAlgorithm;       pattern SSHKEYECDSA   = 3
pattern SSHKEYED25519 :: SshKeyAlgorithm;       pattern SSHKEYED25519 = 4
pattern SSHKEYED448   :: SshKeyAlgorithm;       pattern SSHKEYED448   = 6

pattern SSHSHA2_256   :: SshHashType;           pattern SSHSHA2_256   = 1
pattern SSHSHA2_512   :: SshHashType;           pattern SSHSHA2_512   = 2
