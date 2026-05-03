{- |
Module      : Main
Description : EDNS extension demo
Copyright   : (c) Viktor Dukhovni, 2026
License     : BSD-3-Clause
Maintainer  : ietf-dane@dukhovni.org
Stability   : experimental

A proof of concept demo that extends the @dnsbase@ stub resolver
library with support for sending and receiving the EDNS cookie
option.

In practice applications are unlikely to explicitly manage EDNS
cookies, any real COOKIE support would part of the features of a
fully-fledged *iterative* resolver.  This is much less useful in
stub resolvers, as the iterative resolvers they query are likely
to not enable cookie support for recursive queries.

A real EDNS extension, that an application might elect to
implement, is more likely to implement some other, more useful
option.  This demo highlights the required machinery.
-}

{-# LANGUAGE
    BlockArguments
  , LambdaCase
  , PatternSynonyms
  , RecordWildCards
  , RequiredTypeArguments
  , TemplateHaskell
  , TypeApplications
  #-}
module Main (main) where
import qualified Data.ByteString.Builder as B
import qualified Data.ByteString.Short as SBS
import Control.Monad.Trans.Except (ExceptT(..))
import Data.Coerce (coerce)
import Data.Function ((&))
import Data.Word (Word64)

-- | The "kitchen-sink" import of most of the library.
-- More selective imports of specific submodules are
-- available and of course a qualified import may be
-- a sensible option.
--
import Net.DNSBase

-- | Pretend the codepoint is not yet known to the library,
-- and use a name not likely to conflict with the name
-- chosen when the same code point is added to the library.
--
-- With a qualified import, "COOKIE" would also be fine.
--
pattern EXT_COOKIE :: OptNum
pattern EXT_COOKIE = OptNum 10

-- [EDNS COOKIE](https://datatracker.ietf.org/doc/html/rfc7873#section-4)
--
-- >                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
-- >  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |        OPTION-CODE = 10      |   OPTION-LENGTH >= 16, <= 40   |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                                                               |
-- > +-+-    Client Cookie (fixed size, 8 bytes)              -+-+-+-+
-- > |                                                               |
-- > +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
-- > |                                                               |
-- > /       Server Cookie  (variable size, 8 to 32 bytes)           /
-- > /                                                               /
-- > +-+-+-+-...
--
-- The cold-start client-side cookie has an empty server part,
-- otherwise the server part length is 8 to 32 bytes as above.
--
data T_ext_cookie = T_EXT_COOKIE
    { clientCookie :: Word64              -- ^ Fixed length
    , serverCookie :: SBS.ShortByteString -- ^ Possibly empty
    } deriving (Eq, Ord, Show)

-- | The presentation builders in @dnsbase@ all take a
-- continuation argument, so that a chain of builders
-- becomes b1 <> (b2 <> (b3 <> (... (bN k)...))).
--
instance Presentable T_ext_cookie where
    present T_EXT_COOKIE {..} k =
         B.word64HexFixed clientCookie
         <> present @Bytes16 (coerce serverCookie) k

-- | The minimal required methods are generally
-- sufficient.  Here the only non-required addition
-- is "optPres", which assumes that the codepoint
-- is not yet known to the library.
--
-- Otherwise, all that's needed is the codepoint
-- number, an encoder method and a decoder method.
--
instance KnownEdnsOption T_ext_cookie where
    -- | Required codepoint
    optNum _ = EXT_COOKIE

    -- Optional presentation-form codepoint name, defaults to the
    -- name as known to the library, or else "OPTION<n>".
    --
    optPres _ = present @String "COOKIE"

    -- The total wire-form length is computed internally,
    -- the encoder method does not have to track it.
    --
    optEncode T_EXT_COOKIE {..} = putSizedBuilder $!
        mbWord64 clientCookie
        <> mbShortByteString serverCookie

    -- The decoder hides the polymorphic payload inside the
    -- existential 'EdnsOption' wrapper.  The parser monad makes
    -- sure the lengths consumed exactly match the available input
    -- (get64 raises a @Left why@ with less thatn 8 bytes, the
    -- @len@ argument can be entirely ignored when decoding known
    -- fixed-length inputs.
    --
    optDecode _ _ len = do
         clientCookie <- get64
         serverCookie <-
             if | len == 8 -> pure mempty
                | len > 40 -> failSGet "Server cookie too long"
                | len < 16 -> failSGet "Server cookie too short"
                | otherwise -> getShortNByteString (len - 8)
         pure $ EdnsOption $ T_EXT_COOKIE {..}

-- | Add our EDNS extension to a resolver configuration
--
withCookie :: ResolverConf -> ResolverConf
withCookie = registerEdnsOption T_ext_cookie

-- | None of the usual public resolvers Quad1, Quad8, Quad9
-- or Cisco OpenDNS return EDNS cookies (mostly used only
-- between recursive resolvers and authoritative servers,
-- so this demo reaches out directly to the "isc.org"
-- (maintainers of the BIND DNS software) domain's "ns1"
-- server.
--
-- The "isc.org" nameservers support EDNS cookies only when
-- responding to non-recursive queries (as authoritative
-- servers).  No cookies are returned for queries that
-- request recursion.  So the demo below explicitly turns
-- off the on-by-default "RD" flag in the outgoing query.
--
main :: IO ()
main = do
    -- Should only fail if no IP address can be found for
    -- "ns1.isc.org".
    --
    makeResolvSeed conf >>= \ case
        Left why -> fail (show why)
        Right seed -> withResolver seed go
  where
    -- Compile-time literal domain
    qname = $$(dnLit8 "isc.org")

    -- Runtime string passed to getaddrinfo(3) to
    -- boostrap the resolver.  More typical configurations
    -- load nameserver IP addresses from /etc/resolv.conf
    -- or equivalent, or assume a local resolver and use
    -- "127.0.0.1" or "::1".
    --
    nslist = "ns1.isc.org" :| []
    makeSpec n = NameserverSpec n Nothing

    -- Make a direct non-recursive query to elicit a cookie
    -- from the chosen nameserrver with the extension loaded.
    --
    conf = defaultResolvConf
        & setResolverConfSource (HostList $ makeSpec <$> nslist)
        & setResolverConfQueryControls (QctlFlags (clearFlagBits RDflag))
        & withCookie

    -- This control is applied just-in-time on top of the ambient
    -- resolver configuration, it adds a client cookie with a
    -- random value obtained from the resolver's exported RNG.
    --
    ctls :: Word64 -> QueryControls
    ctls w = EdnsOptionCtl $ optCtlAdd [ EdnsOption $ T_EXT_COOKIE w mempty ]

    go :: Resolver -> IO ()
    go rslv = do
        rnd <- resolvRng rslv

        -- The DNSIO monad is 'ExceptT' with DNSError as the
        -- exception type and 'IO' as the underlying monad.
        --
        -- When chaining multiple actions together that should
        -- short-circuit on the first failure, it is often
        -- convenient to use 'runDNSIO' and handle any error
        -- returned by the overall result.  'ExceptT' wraps
        -- the API's @IO (Either DNSError a)@ to make an
        -- @ExceptT DNSError IO a@.
        --
        ret <- runDNSIO do
            -- Request the full DNS answer.  The resolver makes
            -- sure that the question section of the response
            -- matches the question asked, the query IDS matched,
            -- as did the responder's source IP address and port.
            --
            msg <- ExceptT (lookupRawCtl rslv (ctls rnd) qname IN NS)

            -- Since the query name and type are in the message
            -- the relevant answer RRs can be found from the
            -- message alone.
            --
            rrs <- ExceptT (extractAnswers msg)

            -- The caller gets a composite response or an error
            -- from the first failed step.
            --
            pure (ednsOptions <$> dnsMsgEx msg, rrs)
        case ret of
            Left why -> fail (show why)
            Right (mopts, rrs) -> do
                -- The "mopts" value is a @Maybe [EdnsOption]@
                -- list, because the response might not have used
                -- EDNS at all.  'mapM_' unpacks the outer 'Maybe'
                -- and 'monoOption' filters the list to return
                -- just the elements of the desired type (infered
                -- from the type signature of 'cookout'.
                --
                mapM_ (cookout . monoOption) mopts

                -- The "Presentable" module reexports 'putBuilder'
                -- the fold combines the new-line-terminate
                -- presentation forms of all the answer RRs.
                --
                putBuilder $ foldr presentLn mempty rrs

    -- | Output the cookies in BIND's format, just the
    -- hex nibles of the concatenated client and server
    -- parts (the presentation format of 'T_ext_cookie').
    -- In practice we expect at most one cookie.
    --
    cookout :: [T_ext_cookie] -> IO ()
    cookout cookies = putBuilder $ foldr out mempty cookies
      where
        out cookie k =
            present "; COOKIE: " (presentSpLn cookie k)
