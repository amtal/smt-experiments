{-# LANGUAGE OverloadedStrings #-}
import qualified Data.ByteString.Char8 as B
import Data.SBV
import Data.Char

test init p = crc_msg msg init p 0xE5CC
  where
    msg :: [SWord8]
    msg = parse "123456789"

parse = map (literal . fromIntegral . ord)

main = do
    r <- sat test
    putStrLn $ show r
    let Just s0 = (getModelValue "s0" r)
    putStrLn $ hexS (s0::Word16)
    let Just s1 = (getModelValue "s1" r)
    putStrLn $ hexS (s1::Word16)
    {-
    case r of
        Satisfiable conf model -> do
            putStrLn $ show (modelAssocs model)
            return ()
        _ -> do
            putStrLn $ show ret
            return ()
-}

crc_msg :: [SWord8] -> SWord16 -> SWord16 -> SWord16 -> SBool
crc_msg msg init poly result = foldl step init msg .== result
  where
    step :: SWord16 -> SWord8 -> SWord16
    step last byte = last `xor` crc 16 byte poly

{-
w16 :: Char -> Char -> SWord16
w16 a b = (conv a `shiftL` 8) .|. conv b where
    conv = literal . fromIntegral . ord

step :: SWord16 -> SBool
step poly = crc 16 (0x1234::SWord16) poly .== 0xE5CC

--parse :: String -> [SWord16]
parse = f [] where
    f acc [] = reverse acc
    f acc (a:b:rest) = f (w16 a b:acc) rest    
-}
