{-# LANGUAGE
    BlockArguments
  , RecordWildCards
  , TemplateHaskell
  #-}
import Control.Exception (throwIO)
import Control.Monad.Trans.Except (runExceptT)
import Net.DNSBase
import System.IO (stdout)

main :: IO ()
main = do
    seed <- either throwIO pure =<< runExceptT do
                makeResolvSeed defaultResolvConf
    mxs  <- either throwIO pure =<< runExceptT do
                withResolver seed \r -> lookupMX r $$(dnLit8 "ietf.org")
    hPutBuilder stdout $ foldr presentLn mempty mxs
