{-# LANGUAGE OverloadedStrings, TemplateHaskell #-}
import qualified Data.ByteString.Char8 as B
import Data.SBV
import Data.Char
import Test.QuickCheck hiding ((.&.))
import Data.List (sort)
import Data.Map (toList)
import Data.SBV.Internals (CWVal(..))

--
-- * Analysis
--


-- | Try simplifying problem by forcing state to fA of 0xFFFFffff
--
-- Direct search seems slow, so trying to approach it slowly...
--
-- #17: [95,244,197,151]
-- #18: [0,36,125,34,32,102,253,248]
--  29: [52,7,57,208,48,0,128,28,230,177,1,0,22,64,149,42]
doMaxPop inSz = maximize (Iterative True) maxPop inSz (\_->literal True)
-- where
maxPop block = sPopCount $ fA (hash initSt block) 

test :: [SWord8] -> Symbolic SBool
test block = solve [simplify]
  where
    simplify = fA (hash initSt block) .== 0xFFFFffff

checkSteps :: Int -> Symbolic SBool
-- ^ Okay, suppose we force fA to that - how hard is it to keep it there?
--
-- Looks pretty easy!
checkSteps num = do
    [a,b,c,d] <- (symbolics ["x0", "x1", "x2", "x3"] :: Symbolic [SWord32])
    input <- (mkExistVars num :: Symbolic [SWord8])
    return $ bAnd [ fA (a,b,c,d) .== literal 0xFFFFffff
                  , fA (hash (a,b,c,d) input) .== literal 0xFFFFffff
                  ]

tryDumb :: Int -> Symbolic SBool
-- ^ Hey maybe this is easy!
--
-- Unsat for 1..4, 4 suddenly takes much longer...
-- Oh shiiiit, solution for 5!
--
-- *Main> sat (tryDumb 5)
-- Satisfiable. Model:
--   x0  = 1323788608 :: Word32
--   x1  = 2129112516 :: Word32
--   x2  = 115548480 :: Word32
--   x3  = 3042637503 :: Word32
--   s4  = 128 :: Word8
--   s5  = 193 :: Word8
--   s6  = 235 :: Word8
--   s7  = 9 :: Word8
--   s8  = 127 :: Word8
--   s9  = 20 :: Word8
--   s10 = 121 :: Word8
--   s11 = 239 :: Word8
--   s12 = 137 :: Word8
--   s13 = 103 :: Word8
-- *Main>
-- 
-- GOD DAMN IT even with the NUMS initial state it's 5 steps :'(
{-
*Main> sat $ tryDumb 5
Satisfiable. Model:
  s0 = 133 :: Word8
  s1 = 152 :: Word8
  s2 = 169 :: Word8
  s3 = 138 :: Word8
  s4 = 131 :: Word8
  s5 = 134 :: Word8
  s6 = 160 :: Word8
  s7 = 169 :: Word8
  s8 = 138 :: Word8
  s9 = 122 :: Word8
-}
tryDumb num = do
    --[a,b,c,d] <- (symbolics ["x0", "x1", "x2", "x3"] :: Symbolic [SWord32])
    seq1 <- (mkExistVars num :: Symbolic [SWord8])
    seq2 <- (mkExistVars num :: Symbolic [SWord8])
    return $ bAnd [ hash initSt seq1 .== hash initSt seq2
                  , seq1 ./= seq2
                  --, fA (a,b,c,d) .== literal 0xFFFFffff
                  ]

easyWin = ([133,152,169,138,131], [134,160,169,138,122])

-- | While we're here, invert shuf the practical way
unshuf :: [SWord8] -> IO [Integer]
unshuf seq = do
    let prob = do
        seqIn <- mkExistVars 128
        let seqOut = seq ++ take (128 - length seq) (repeat 0)
        return (shuf seqIn .== seqOut)
    mod <- sat prob
    let lol = toList . getModelDictionary $ mod
        lol2 = sort [(take (4 - length name) (repeat '0') ++ name,val) | (_:name,val)<-lol]
        lol3 = map snd lol2 -- lololol
    return $ map (\(CWInteger n)->n) $ map cwVal lol3
    -- screw it, using Python bindings next time :\

--
-- * Core function implementation for analysis
--



type SWord128 = (SWord32, SWord32, SWord32, SWord32)
s128 (a,b,c,d) = map hex [a,b,c,d]

initSt :: SWord128 
initSt = (0xdeadbeef, 0xcafebabe, 0xbad1dea, 0xfacefeed)

-- | Compression strongly trending towards 0xFFFFffff
--
-- Strong simplification candidate!
fA (x0,x1,x2,x3) = (x0 .&. x1) .|. (complement x2 .&. x3)
-- | Independent of data
fInd st@(_,x1,_,_) = (x1 + fA st, 0, 0, 0)
-- | Data-dependent
fDep byte = (dw, dw `shiftL` 3, dw `shiftL` 7, 0) where 
    dw = (extend . extend) byte 

($+) (a,b,c,d) (w,x,y,z) = (a+w,b+x,c+y,d+z)

hash :: SWord128 -> [SWord8] -> SWord128
-- ^ Unpadded, unshufd.
hash msg = foldl step msg
  where
    step :: SWord128 -> SWord8 -> SWord128
    step st byte = roll (fInd st $+ fDep byte $+ st)
    roll (x0,x1,x2,x3) = (x3,x0,x1,x2)


--
-- * Full function implementation, just for C round trip KAT
--
--

fullHash :: [SWord8] -> SWord128
-- ^ Full hash implementation for C KATs
fullHash xs = walk (pad xs) initSt
  where
    walk [] st = st
    walk xs st = walk (drop 128 xs) (($+) st . hash st . shuf $ take 128 xs)


prop_kat_short = (0x9d0e8cb6, 0x988bc463, 0x3c853149, 0xc66a1fea) == fullHash [0x61, 0x62, 0x63]
prop_kat_long = (0x266bf9bc, 0xf22b1ca5, 0xc7329b67, 0x807dc585) == fullHash msg where
    msg = take 129 $ repeat 0x61


-- | Index-based shuffle.
shuf xs | 128 == length xs = [xs !! ((0x4f * n) `mod` 128) | n <- [0..127]]

pad :: [SWord8] -> [SWord8]
-- ^ Length-suffixed pad
pad msg = msg ++ take padLen (repeat (literal 0)) ++ le32 (length msg)
  where
    padLen = case length msg of 
        125 -> 127
        126 -> 126
        127 -> 125
        128 -> 124 
        _   -> 124 - (length msg `mod` 128)
    le32 :: Int -> [SWord8]
    le32 n = map (literal . fromIntegral . (.&. 0xFF) . shiftR n) [0, 8, 16, 24]

prop_pad_stride xs = 0 == length (pad xs) `mod` 128 -- needs a resize hint to catch edge :\
prop_pad_len xs = 128 <= length (pad xs)
prop_pad_fin xs = 
    let storedLen = pad xs !! (length (pad xs) - 4)
    in storedLen == (literal . fromIntegral . length $ xs)
prop_shuf = [0..127] == sort (shuf [0..127])

return []
runTests = $quickCheckAll
