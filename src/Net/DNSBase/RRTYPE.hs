module Net.DNSBase.RRTYPE
    ( -- * DNS Resource Record type numbers
      RRTYPE(..)
      -- ** Corresponding type-level Naturals
    , type N_a
    , type N_ns
    , type N_md
    , type N_mf
    , type N_cname
    , type N_soa
    , type N_mb
    , type N_mg
    , type N_mr
    , type N_null
    , type N_wks
    , type N_ptr
    , type N_hinfo
    , type N_minfo
    , type N_mx
    , type N_txt
    , type N_rp
    , type N_afsdb
    , type N_x25
    , type N_isdn
    , type N_rt
    , type N_nsap
    , type N_nsapptr
    , type N_sig
    , type N_key
    , type N_px
    , type N_gpos
    , type N_aaaa
    , type N_loc
    , type N_nxt
    , type N_eid
    , type N_nimloc
    , type N_srv
    , type N_atma
    , type N_naptr
    , type N_kx
    , type N_cert
    , type N_a6
    , type N_dname
    , type N_sink
    , type N_opt
    , type N_apl
    , type N_ds
    , type N_sshfp
    , type N_ipseckey
    , type N_rrsig
    , type N_nsec
    , type N_dnskey
    , type N_nsec3
    , type N_nsec3param
    , type N_tlsa
    , type N_smimea
    , type N_cds
    , type N_cdnskey
    , type N_openpgpkey
    , type N_csync
    , type N_zonemd
    , type N_svcb
    , type N_https
    , type N_dsync
    , type N_nid
    , type N_l32
    , type N_l64
    , type N_nxname
    , type N_ixfr
    , type N_axfr
    , type N_mailb
    , type N_maila
    , type N_any
    , type N_caa
    , type N_amtrelay
    ) where

import Net.DNSBase.Internal.RRTYPE
