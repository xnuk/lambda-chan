{-# LANGUAGE OverloadedStrings, FlexibleInstances #-}
import qualified Prelude
import Prelude hiding (putStr, putStrLn)
import Network.Socket (socket, getAddrInfo, AddrInfo(..), HostName)
import qualified Network.Socket as Sock
import Network.TLS (defaultParamsClient, handshake, clientSupported, clientShared, sharedValidationCache, ValidationCache(..), ValidationCacheResult(ValidationCachePass), supportedCiphers, supportedSecureRenegotiation)
import Network.TLS.Extra.Cipher (ciphersuite_all)
import qualified Network.TLS as TLS
import Control.Monad
import Control.Exception
import Crypto.Random (createEntropyPool, CPRG(..), SystemRNG)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as LazyBS
import qualified Data.ByteString.UTF8 as BSU
import qualified Data.ByteString.Lazy.UTF8 as LazyBSU
import Data.ByteString.Lazy (fromStrict)
import Data.Default (def)
import System.Process (readProcessWithExitCode)
import System.Exit (ExitCode(ExitFailure))
import Data.Text.Lazy (strip)
import qualified Data.Text.Lazy as LazyT
import Data.Word (Word8)
import Pointfree (pointfree')
import Lambdabot.Pointful (pointful)
import Data.Text.Lazy.Encoding (encodeUtf8, decodeUtf8)

class IsString a where
    fromString :: String -> a
    toString :: a -> String
    (<+) :: a -> a-> a
    isPrefixOf :: a -> a -> Bool
    isSuffixOf :: a -> a -> Bool

instance IsString [Char] where
    fromString xs = xs
    toString xs = xs
    (<+) = (++)
    isPrefixOf a b = BS.isPrefixOf (fromString a) (fromString b)
    isSuffixOf a b = BS.isSuffixOf (fromString a) (fromString b)

instance IsString LazyBS.ByteString where
    fromString = LazyBSU.fromString
    toString = LazyBSU.toString
    (<+) = LazyBS.append
    isPrefixOf = LazyBS.isPrefixOf
    isSuffixOf = LazyBS.isSuffixOf

instance IsString BS.ByteString where
    fromString = BSU.fromString
    toString = BSU.toString
    (<+) = BS.append
    isPrefixOf = BS.isPrefixOf
    isSuffixOf = BS.isSuffixOf

putStr :: IsString a => a -> IO ()
putStr = Prelude.putStr . toString

putStrLn :: IsString a => a -> IO ()
putStrLn = Prelude.putStrLn . toString

lf, sp :: Word8
channels :: [LazyBS.ByteString]
serverport :: Sock.PortNumber
svrdomain :: HostName
botnick :: LazyBS.ByteString

lf = LazyBS.head "\n"
sp = LazyBS.head " "
botnick=LazyBSU.fromString "lambdaChan"
svrdomain="irc.uriirc.org"
serverport=16667
channels=["#foobar", "#hyeon"]


muevalpath :: IO String
muevalpath = flip liftM (readFile "muevalpath.txt") $
            LazyT.unpack . strip . LazyT.pack

if' :: Bool -> a -> a -> a
if' True  a _=a
if' False _ a=a

muoption :: IO [String]
muoption =
    liftM2 (++)
          (flip liftM (readFile "trusted.txt") $
             (["--no-imports", "--load-file=L.hs", "--package-trust", "--time-limit=4"]++)
             . lns "-s")
          (flip liftM (readFile "exts.txt") $ lns "-X")
    where lns x = fmap ((x++) . LazyT.unpack)
                  . LazyT.splitOn "\n" . strip . LazyT.pack

main :: IO ()
main=do
    a <- getAddrInfo Nothing (Just svrdomain) (Just (show serverport))
    let addrinfo=filter ((==Sock.Stream).addrSocketType) a
    mapM_ (print . addrAddress) addrinfo
    connect addrinfo

connect :: [AddrInfo] -> IO ()
connect [] = return ()
connect (adinfo:adinfos) = do
    sock <- socket (addrFamily adinfo) (addrSocketType adinfo) (addrProtocol adinfo)
    ep <- createEntropyPool
    let t=(defaultParamsClient "irc.uriirc.org" BS.empty) {
        clientSupported=def {
            supportedCiphers=ciphersuite_all,
            supportedSecureRenegotiation=False
        }, clientShared=def {
            sharedValidationCache = ValidationCache (\_ _ _ -> return ValidationCachePass) (\_ _ _ -> return ())
        }
    }
    ctx <- TLS.contextNew sock t (cprgCreate ep :: SystemRNG)
    cn <- try $ Sock.connect sock (addrAddress adinfo)
    case cn of
        Left (SomeException _) -> do
            putStrLn $ 'C':"annot connect"
            Sock.close sock
            connect adinfos
        Right _ -> do
            handshake ctx
            let send x = do
                    putStr $ '-':"> "
                    print x
                    TLS.sendData ctx x -- x is Lazy ByteString
                recv = TLS.recvData ctx -- return value is Strict ByteString
            bs <- recv
            putStrLn bs
            send $ "NICK " <+ botnick <+ "\r\nUSER " <+ botnick <+ " Xnuktest XnukChan :a s\r\n"
            bss <- recv
            putStrLn bss
            mapM_ (send . (<+ "\r\n") . ("JOIN " <+)) channels
            send "JOIN #foobar\r\n"
            mainLoop "" send recv ""
    return ()

mainLoop :: LazyBS.ByteString -> (LazyBS.ByteString -> IO ()) -> IO BS.ByteString -> LazyBS.ByteString -> IO ()
mainLoop rest send recv pingval = do
    ch <- recv
    let a = LazyBS.split lf $ rest <+ fromStrict ch
    let isch = if' ("\r\n" `isSuffixOf` last a)
    let chunk = isch "" (last a)
    let ls = isch a (init a)
    mapM_ (parseLine send pingval) ls
    mapM_ putStrLn ls
    mainLoop chunk send recv pingval
    return ()

parseLine :: (LazyBS.ByteString -> IO ()) -> LazyBS.ByteString -> LazyBS.ByteString -> IO ()
parseLine send pingval line
    | prfx "PING :" = send $ fromString "PONG :" <+ pingval <+ "\r\n"
    | cmd ">>" = do
        x <- runMueval False afcmd
        case x of "" -> return ()
                  v  -> send . LazyBS.concat . map privstr . take 3 . LazyBS.split lf $ v
    | cmd ":t" = do
        x <- runMueval True afcmd
        case x of "" -> return ()
                  v  -> send . LazyBS.concat . map privstr . take 3 . LazyBS.split lf $ v
    | cmd "@pl" = case (pointfree'.toString) afcmd of Just x  -> send.privstr.fromString $ x
                                                      Nothing -> send.privstr $ "No result"
    | cmd "@unpl" = send.privstr.fromString.pointful.toString $ afcmd
    | otherwise = return ()
    where prfx = (`isPrefixOf` line) . fromString
          ws = LazyBS.split sp line
          priv = ws!!1 == fromString "PRIVMSG" && isPrefixOf (fromString "#") (ws!!2)
          cmd x = length ws > 4 && priv && ":"<+x == (ws!!3)
          afcmd = encodeUtf8.strip.decodeUtf8 $ LazyBS.intercalate " " $ drop 4 ws
          privstr = (<+ "\r\n") . LazyBS.intercalate " " . ([ws!!1, ws!!2]++) . (:[]) . (fromString ":" <+)

runMueval :: Bool -> LazyBS.ByteString -> IO LazyBS.ByteString
runMueval istype str
    | xs=="" = return ""
    | istype = do
        muoptions <- muoption
        mupath <- muevalpath
        (exitcode, out, err) <- readProcessWithExitCode mupath (muoptions ++ ["-T", "-i", "--expression=" ++ toString xs]) ""
        case (out, err) of ([], []) -> return "Terminated"
                           _ -> return $ case () of {_
                                | null out && null err -> "Terminated"
                                | exitcode == ExitFailure 1 && not (null out) -> trim (fromString out :: LazyBS.ByteString)
                                | otherwise -> trim . LazyBS.intercalate "\n" . tail $ LazyBS.split lf (fromString out :: LazyBS.ByteString)
                           }
    | otherwise = do
        muoptions <- muoption
        mupath <- muevalpath
        (_, out, err) <- readProcessWithExitCode mupath (muoptions ++ ["--expression=" ++ toString xs]) ""
        case (out, err) of ([], []) -> return "Terminated"
                           _ -> return $ case () of {_
                                | null out && null err -> "Terminated"
                                | null out -> trim (fromString err :: LazyBS.ByteString)
                                | otherwise ->
                                    if x == "" then " "
                                               else x
                                    where x = trim (fromString out :: LazyBS.ByteString)
                           }
    where trim = encodeUtf8.strip.decodeUtf8
          xs = trim str
