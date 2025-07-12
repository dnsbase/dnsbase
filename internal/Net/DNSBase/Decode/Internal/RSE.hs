{-# LANGUAGE CPP #-}

module Net.DNSBase.Decode.Internal.RSE
    ( RSE(..)
    , evalRSE
    , execRSE
    , ask
    , asks
    , get
    , gets
    , local
    , modify
    , modify'
    , put
    , throwRSE
    , catchRSE
    , handleRSE
    ) where

#if !MIN_VERSION_base(4,18,0)
import Control.Applicative(Applicative(..))
#endif

-- | Minimal Reader + State + Except Monad.
newtype RSE e r s a = RSE { runRSE :: r -> s -> Either e (a, s) }

evalRSE :: RSE e r s a -> r -> s -> Either e a
evalRSE m = \r s -> fst <$> runRSE m r s
{-# INLINE evalRSE #-}

execRSE :: RSE e r s a -> r -> s -> Either e s
execRSE m = \r s -> snd <$> runRSE m r s
{-# INLINE execRSE #-}

instance Functor (RSE e r s) where
    fmap f m = RSE $ \r s -> do
        (a, t) <- runRSE m r s
        pure (f a, t)
    {-# INLINE fmap #-}

instance Applicative (RSE e r s) where
    pure a = RSE $ \_ s -> pure (a, s)
    {-# INLINE pure #-}
    mf <*> ma = RSE $ \r s -> do
        (f, t) <- runRSE mf r s
        (a, u) <- runRSE ma r t
        pure (f a, u)
    {-# INLINE (<*>) #-}
    liftA2 f ma mb = RSE $ \r s -> do
        (a, t) <- runRSE ma r s
        (b, u) <- runRSE mb r t
        pure (f a b, u)
    {-# INLINE liftA2 #-}
    ma *> mb = RSE $ \r s -> do
        (_, t) <- runRSE ma r s
        runRSE mb r t
    {-# INLINE (*>) #-}
    ma <* mb = RSE $ \r s -> do
        (a, t) <- runRSE ma r s
        (_, u) <- runRSE mb r t
        pure (a, u)
    {-# INLINE (<*) #-}

instance Monad (RSE e r s) where
    ma >>= f = RSE $ \r s -> do
        (a, t) <- runRSE ma r s
        runRSE (f a) r t
    {-# INLINE (>>=) #-}

ask :: RSE e r s r
ask  = RSE $ \r s -> pure (r, s)
{-# INLINE ask #-}

asks  :: (r -> a) -> RSE e r s a
asks f = RSE $ \r s -> pure (f r, s)
{-# INLINE asks #-}

get :: RSE e r s s
get = RSE $ \_ s -> pure (s, s)
{-# INLINE get #-}

gets  :: (s -> a) -> RSE e r s a
gets f = RSE $ \_ s -> pure (f s, s)
{-# INLINE gets #-}

local :: (r -> r) -> RSE e r s a -> RSE e r s a
local f m = RSE $ \ r s -> runRSE m (f r) s
{-# INLINE local #-}

modify  :: (s -> s) -> RSE e r s ()
modify f = RSE $ \_ s -> pure ((), f s)
{-# INLINE modify #-}

modify'  :: (s -> s) -> RSE e r s ()
modify' f = RSE $ \_ s -> let !t = f s in pure ((), t)
{-# INLINE modify' #-}

put  :: s -> RSE e r s ()
put !s = RSE $ \_ _ -> pure ((), s)
{-# INLINE put #-}

throwRSE :: e -> RSE e r s a
throwRSE e = RSE $ \_ _ -> Left e
{-# INLINE throwRSE #-}

catchRSE :: RSE e r s a -> (e -> RSE f r s a) -> RSE f r s a
catchRSE ma h = RSE $ \r s -> case runRSE ma r s of
    Right (a, t) -> pure (a, t)
    Left      e  -> runRSE (h e) r s
{-# INLINE catchRSE #-}

handleRSE :: (e -> RSE f r s a) -> RSE e r s a -> RSE f r s a
handleRSE = flip catchRSE
{-# INLINE handleRSE #-}
