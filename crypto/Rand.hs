{-# LANGUAGE OverloadedStrings #-}
import qualified Data.ByteString.Char8 as B
import Data.SBV
import Data.Char
import Data.List

parse = map (literal . fromIntegral . ord)

msg :: [SWord8]
msg = parse "123456789"

randStep, randOut :: SWord32 -> SWord32
randStep s = s * 1103515245 + 12345
randOut x = (x `sbvShiftRight` (16::SWord32)) .&. 0x7Fff

rand seed = unfoldr f seed where
    f s = let s' = randStep s in Just (randOut s', s') 
    
reduced = map (`sRem` 0xff) . rand

-- non-reduced output
seen :: [SWord32]
--seen = [16838,5758,10113,17515,31051,5627,23010,7419,16212,4086]

-- reduced output
--seen = [8,148,168,175,196,17,60,24,147,6,199,17,159,75,95,203,99,18,147,66,191,133,95,111,147,219,201,140,247,236,179,200]

-- reduced output seed 1337
--seen = unhex "b36be9c82722834b73701680460fa9fb1b3198949f89881102b9390daa41951c"

-- foldl1 (++) $ map (drop 6 . hex) $ take 32 $ reduced 0xdeadbeef
seen = unhex "1d5831be87dc9d98e53023b62dd89dd137d9441cba9cbd0de8a1efc417f45ad5"
-- *Main> main
-- Seed #1: 0x5eadbeef :: Word32
-- Seed #2: 0xdeadbeef :: Word32
-- Found: 2 seed(s).

unhex :: String -> [SWord32]
unhex = f [] where
    f acc [] = reverse acc
    f acc (a:b:rest) = f (fromIntegral (h a * 0x10 + h b):acc) rest
    h c | '0' <= c && c <= '9' = ord c - ord '0'
        | 'a' <= c && c <= 'f' = ord c - ord 'a' + 10

main = do
    res <- allSat $ do
        seed <- exists "seed"
        return $ foldl1 (&&&) $ zipWith (.==) seen (take 32 $ reduced seed)
    cnt <- displayModels disp res
    putStrLn $ "Found: " ++ show cnt ++ " seed(s)."
        where disp :: Int -> (Bool, Word32) -> IO ()
              disp n (_, s) = putStrLn $ "Seed #" ++ show n ++ ": " ++ hexS s

