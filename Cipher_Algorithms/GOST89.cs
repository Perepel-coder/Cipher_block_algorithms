using Cipher.Cipher_Tools;
using Mathematics;

namespace Cipher.Cipher_Algorithms
{
    public class GOST89 : ICipherBlockAlgorithm
    {
        private readonly int numWBlock;        // кол-во слов в блоке
        private readonly int numWKey;          // кол-во слов в ключе
        private readonly int numBWord;         // кол-во байт в слове (длина слова)
        private readonly int numRound;         // кол-во раундов
        private readonly int numKey;           // кол-во ключей
        private readonly char defaultChar;     // дополняющий символ

        public int BlockSize { get; }

        public GOST89(char defaultChar)
        {
            this.defaultChar = defaultChar;
            this.numWKey = 1;
            this.numWBlock = 2;
            this.numBWord = 4;
            this.numKey = 8;
            this.numRound = 4;
            this.BlockSize = this.numWBlock * this.numBWord;
        }

        /// <summary>
        /// Вычисление раундных ключей для всех раундов
        /// </summary>
        private List<Word> ExpandKey(List<byte> key)
        {
            List<Word> NewKey = new();
            while (key.Count % (this.numWKey * this.numBWord) != 0) { key.Add((byte)defaultChar); }
            for (int i = 0, j = 0; i < key.Count; i += 4)
            {
                if (NewKey.Count != (this.numKey * this.numWKey))
                {
                    NewKey.Add(new Word(key, i));
                }
                else
                {
                    NewKey[j] = NewKey[j].XOR(new Word(key, i));
                    if (j < this.numKey * this.numWKey - 1) { j++; }
                    else { j = 0; }
                }
            }
            int counter = this.numWKey * this.numKey;
            int start = NewKey.Count;
            for (int i = start; i < counter; i++)
            {
                Word temp = NewKey[i - 1];
                if (i % this.numWKey == 0)
                {
                    Word Word1 = (temp.RotWordLeft()).SubWord();
                    int b1 = (int)Math.Pow(2, i / this.numWKey);
                    if (b1 > 128) { b1 = MathematicsGF.DivOfPolyGF(b1, 283)[1]; }
                    Word Word2 = new() { Byte1 = (byte)b1 };
                    temp = Word1.XOR(Word2);
                }
                else if ((this.numWKey > 6) && (i % this.numWKey == 4)) { temp = temp.SubWord(); }
                NewKey.Add(NewKey[i - this.numWKey].XOR(temp));
            }
            return NewKey;
        }

        /// <summary>
        /// Создание инициализирующего вектора
        /// </summary>
        /// <param name="vector"></param>
        /// <returns></returns>
        private List<byte> CreatInitVector(int vector, int numBlocks)
        {
            List<byte> initVec = new();
            for (int j = 1; j <= numBlocks; j++)
            {
                for (int i = 1; i <= this.numWBlock; i++)
                {
                    Random random = new(vector);
                    vector = random.Next() ^ i ^ j;
                    string result = Convert.ToString(vector, 16);
                    while (result.Length < 8) { result = Convert.ToString(0) + result; }
                    initVec.Add(Convert.ToByte(result[0..2], 16));
                    initVec.Add(Convert.ToByte(result[2..4], 16));
                    initVec.Add(Convert.ToByte(result[4..6], 16));
                    initVec.Add(Convert.ToByte(result[6..8], 16));
                }
            }
            return initVec;
        }
        private static Word[] XorBlocks(Word[] block1, Word[] block2, int size)
        {
            Word[] result = new Word[size];
            for (int i = 0; i < size; i++)
            {
                result[i] = block1[i].XOR(block2[i]);
            }
            return result;
        }

        #region CriptoFunction
        private static string RotLeft(char[] myStr)
        {
            char cup = myStr[0];
            string result = string.Empty;
            for (int i = 1; i < myStr.Length; i++)
            {
                result += myStr[i];
            }
            result += cup;

            return result;
        }
        private static string RotRight(char[] myStr)
        {
            string result = myStr[^1].ToString();
            for (int i = 0; i < myStr.Length - 1; i++)
            {
                result += myStr[i];
            }
            return result;
        }
        private static byte SubBit(byte myByte, int index)
        {
            string resultBit = Convert.ToString(myByte, 2);
            while (resultBit.Length < 4) { resultBit = '0' + resultBit; }
            for (int i = 0; i <= index; i++)
            {
                resultBit = GOST89.RotLeft(resultBit.ToArray());
            }
            byte res = Convert.ToByte(resultBit, 2);
            res ^= (byte)(index + 1);
            return res;
        }
        private static byte InvSubBit(byte myByte, int index)
        {
            myByte ^= (byte)(index + 1);
            string resultBit = Convert.ToString(myByte, 2);
            while (resultBit.Length < 4) { resultBit = '0' + resultBit; }
            for (int i = 0; i <= index; i++)
            {
                resultBit = GOST89.RotRight(resultBit.ToArray());
            }
            byte res = Convert.ToByte(resultBit, 2);
            return res;
        }
        #endregion

        #region Преобразование List<byte> в List<Word[]>
        private int CountOfBlocks(IEnumerable<byte> inputData)
        {
            int size = inputData.Count();
            while (size % (this.numWBlock * this.numBWord) != 0) { size++; }
            return size / (this.numWBlock * this.numBWord);
        }
        private void GetWordsViewFromByte(List<byte> inputData, List<Word[]> currentData)
        {
            int size = CountOfBlocks(inputData);
            while (inputData.Count / (this.numWBlock * this.numBWord) != size) { inputData.Add((byte)defaultChar); }
            int j = 0;
            for (int i = 0; i < size; i++)
            {
                currentData.Add(new Word[this.numWBlock]);

                for (int x = 0; x < currentData[i].Length; x++, j += 4)
                {
                    currentData[i][x] = new(inputData, j);
                }
            }
        }
        private IEnumerable<byte> GetResultData(List<Word[]> currentData, bool flag)
        {
            List<byte> code = new();
            foreach (var block in currentData)
            {
                foreach (Word word in block)
                {
                    code.Add(word.Byte1);
                    code.Add(word.Byte2);
                    code.Add(word.Byte3);
                    code.Add(word.Byte4);
                }
            }
            if (flag)
            {
                return code;
            }
            else
            {
                int indexDefChar = code.IndexOf((byte)this.defaultChar);
                if (indexDefChar < 0) { return code; }
                return ((code.ToArray())[0..indexDefChar]).ToList();
            }
        }
        #endregion

        private void EncodeBlock(Word[] block, List<Word> currentKey)
        {

            void Step(Word key)
            {
                Word olderPart = block[0];
                Word youngerPart = block[1];
                youngerPart = youngerPart.MultGF(key, 4299161607);
                #region SubBytes
                string stringView = youngerPart.GetStringView16();
                string arrayS = string.Empty;
                for (int i = 0; i < stringView.Length; i++)
                {
                    byte res = GOST89.SubBit(Convert.ToByte(stringView[i].ToString(), 16), i);
                    arrayS += Convert.ToString(res, 16);
                }
                youngerPart = new Word
                {
                    Byte1 = Convert.ToByte(arrayS[0..2], 16),
                    Byte2 = Convert.ToByte(arrayS[2..4], 16),
                    Byte3 = Convert.ToByte(arrayS[4..6], 16),
                    Byte4 = Convert.ToByte(arrayS[6..8], 16)
                };
                #endregion

                #region RotLeft() << 11
                stringView = youngerPart.GetStringView2();
                for (int i = 0; i < 11; i++)
                {
                    stringView = GOST89.RotLeft(stringView.ToArray());
                }
                stringView = Convert.ToString((long)Convert.ToUInt64(stringView, 2), 16);
                while (stringView.Length < 8) { stringView = Convert.ToString(0) + stringView; }
                youngerPart = new Word
                {
                    Byte1 = Convert.ToByte(stringView[0..2], 16),
                    Byte2 = Convert.ToByte(stringView[2..4], 16),
                    Byte3 = Convert.ToByte(stringView[4..6], 16),
                    Byte4 = Convert.ToByte(stringView[6..8], 16)
                };
                #endregion

                olderPart = youngerPart.XOR(olderPart);
                block[0] = youngerPart;
                block[1] = olderPart;
            }

            for (int i = 0; i < this.numRound; i++)
            {
                if (i != 3)
                {
                    for (int j = 0; j < this.numKey; j++) { Step(currentKey[j]); }
                }
                else
                {
                    for (int j = this.numKey - 1; j >= 0; j--) { Step(currentKey[j]); }
                }
            }
        }
        private void DecodeBlock(Word[] block, List<Word> currentKey)
        {
            void Step(Word key)
            {
                Word youngerPart = block[0];
                Word olderPart = block[1].XOR(youngerPart);

                #region RotRight() << 11
                var t = youngerPart.GetStringView16();
                string stringView = youngerPart.GetStringView2();
                for (int i = 0; i < 11; i++)
                {
                    stringView = GOST89.RotRight(stringView.ToArray());
                }
                stringView = Convert.ToString((long)Convert.ToUInt64(stringView, 2), 16);
                while (stringView.Length < 8) { stringView = Convert.ToString(0) + stringView; }
                youngerPart = new Word
                {
                    Byte1 = Convert.ToByte(stringView[0..2], 16),
                    Byte2 = Convert.ToByte(stringView[2..4], 16),
                    Byte3 = Convert.ToByte(stringView[4..6], 16),
                    Byte4 = Convert.ToByte(stringView[6..8], 16)
                };
                #endregion

                #region SubBytes
                stringView = youngerPart.GetStringView16();
                string arrayS = string.Empty;
                for (int i = 0; i < stringView.Length; i++)
                {
                    byte res = GOST89.InvSubBit(Convert.ToByte(stringView[i].ToString(), 16), i);
                    arrayS += Convert.ToString(res, 16);
                }
                youngerPart = new Word
                {
                    Byte1 = Convert.ToByte(arrayS[0..2], 16),
                    Byte2 = Convert.ToByte(arrayS[2..4], 16),
                    Byte3 = Convert.ToByte(arrayS[4..6], 16),
                    Byte4 = Convert.ToByte(arrayS[6..8], 16)
                };
                #endregion

                long insertKey = MathematicsGF.InversionPolynomialGF(key.GetLongView32(), 4299161607);
                youngerPart = youngerPart.MultGF(insertKey, 4299161607);
                block[0] = olderPart;
                block[1] = youngerPart;
            }

            for (int i = 0; i < this.numRound; i++)
            {
                if (i == 0)
                {
                    for (int j = 0; j < this.numKey; j++) { Step(currentKey[j]); }
                }
                else
                {
                    for (int j = this.numKey - 1; j >= 0; j--) { Step(currentKey[j]); }
                }
            }
        }

        #region Interface implementation ICipher

        /// <summary>
        /// Закодировать GOST89 ECB режим
        /// </summary>
        /// <param name="inputData"> входные данные </param>
        /// <param name="key"> ключ </param>
        public IEnumerable<byte> EncodeECB(IEnumerable<byte> inputData, IEnumerable<byte> key)
        {
            if (inputData.Count() == 0 || key.Count() == 0) { return inputData; }
            List<Word[]> currentData = new();
            bool flag = true;
            if (inputData.Count() % (this.numWBlock * this.numBWord) == 0) { flag = false; }
            this.GetWordsViewFromByte(inputData.ToList(), currentData);

            List<Word> currentKey = this.ExpandKey(key.ToList());
            for (int i = 0; i < currentData.Count; i++)
            {
                EncodeBlock(currentData[i], currentKey);
            }
            return this.GetResultData(currentData, flag);
        }

        /// <summary>
        /// Раскодировать GOST89 ECB режим
        /// </summary>
        /// <param name="inputData"> входные данные </param>
        /// <param name="key"> ключ </param>
        /// <returns> расшифровка </returns>
        /// <exception cref="Exception"></exception>
        public IEnumerable<byte> DecodeECB(IEnumerable<byte> inputData, IEnumerable<byte> key)
        {
            if (inputData.Count() == 0 || key.Count() == 0) { return inputData; }
            List<Word[]> currentData = new();
            bool flag = true;
            if (inputData.Count() % (this.numWBlock * this.numBWord) == 0) { flag = false; }
            this.GetWordsViewFromByte(inputData.ToList(), currentData);

            List<Word> currentKey = this.ExpandKey(key.ToList());
            for (int i = 0; i < currentData.Count; i++)
            {
                DecodeBlock(currentData[i], currentKey);
            }
            return this.GetResultData(currentData, flag);
        }

        /// <summary>
        /// Закодировать GOST89 CBC режим
        /// </summary>
        /// <param name="inputData"> входные данные </param>
        /// <param name="key"> входные данные </param>
        /// <param name="initVector"> управлябщий вектор </param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public IEnumerable<byte> EncodeCBC(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector)
        {
            if (inputData.Count() == 0 || key.Count() == 0) { return inputData; }
            List<Word[]> currentData = new();
            bool flag = true;
            if (inputData.Count() % (this.numWBlock * this.numBWord) == 0) { flag = false; }
            this.GetWordsViewFromByte(inputData.ToList(), currentData);

            List<Word[]> vec = new();
            this.GetWordsViewFromByte(this.CreatInitVector(initVector, inputData.Count() / (this.numWBlock * this.numBWord)), vec);

            List<Word> currentKey = this.ExpandKey(key.ToList());

            for (int i = 0; i < currentData.Count; i++)
            {
                if (i == 0) { currentData[0] = GOST89.XorBlocks(vec[0].ToArray(), currentData[0], this.numWBlock); }
                else { currentData[i] = GOST89.XorBlocks(currentData[i - 1], currentData[i], this.numWBlock); }
                EncodeBlock(currentData[i], currentKey);
            }
            return this.GetResultData(currentData, flag);
        }

        /// <summary>
        ///  Раскодировать GOST89 CBC режим
        /// </summary>
        /// <param name="inputData"> входные данные </param>
        /// <param name="key"> входные данные </param>
        /// <param name="intVec"> управлябщий вектор </param>
        /// <returns></returns>
        public IEnumerable<byte> DecodeCBC(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector)
        {
            if (inputData.Count() == 0 || key.Count() == 0) { return inputData; }
            List<Word[]> currentData = new();
            bool flag = true;
            if (inputData.Count() % (this.numWBlock * this.numBWord) == 0) { flag = false; }
            this.GetWordsViewFromByte(inputData.ToList(), currentData);

            List<Word[]> vec = new();
            this.GetWordsViewFromByte(this.CreatInitVector(initVector, inputData.Count() / (this.numWBlock * this.numBWord)), vec);
            List<Word> currentKey = this.ExpandKey(key.ToList());
            List<Word[]> cipherData = new();
            foreach (var el in currentData)
            {
                Word[] block = new Word[this.numWBlock];
                Array.Copy(el, block, this.numWBlock);
                cipherData.Add(block);
            }
            for (int i = 0; i < currentData.Count; i++)
            {
                DecodeBlock(currentData[i], currentKey);
                if (i == 0) { currentData[0] = GOST89.XorBlocks(vec[0].ToArray(), currentData[0], this.numWBlock); }
                else { currentData[i] = GOST89.XorBlocks(cipherData[i - 1], currentData[i], this.numWBlock); }
            }
            return this.GetResultData(currentData, flag);
        }

        public IEnumerable<byte> EncodeGammingECB(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector)
        {
            if (inputData.Count() == 0 || key.Count() == 0) { return inputData; }
            int numOfBlocks = CountOfBlocks(inputData);
            List<Word[]> gammaWords = new();
            List<byte> gammaBytes = this.CreatInitVector(initVector, numOfBlocks);
            for (int i = 0; i < inputData.Count(); i++) { gammaBytes[i] ^= inputData.ToList()[i]; }
            this.GetWordsViewFromByte(gammaBytes, gammaWords);
            List<Word> currentKey = this.ExpandKey(key.ToList());
            for (int i = 0; i < gammaWords.Count; i++)
            {
                EncodeBlock(gammaWords[i], currentKey);
            }
            return this.GetResultData(gammaWords, true);
        }

        public IEnumerable<byte> DecodeGammingECB(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector)
        {
            if (inputData.Count() == 0 || key.Count() == 0) { return inputData; }
            List<Word[]> gammaWords = new();
            int numOfBlocks = CountOfBlocks(inputData);
            this.GetWordsViewFromByte(inputData.ToList(), gammaWords);
            List<Word> currentKey = this.ExpandKey(key.ToList());
            for (int i = 0; i < gammaWords.Count; i++)
            {
                DecodeBlock(gammaWords[i], currentKey);
            }
            List<byte> gamma = this.CreatInitVector(initVector, numOfBlocks);
            List<byte> gammaBytes = this.GetResultData(gammaWords, true).ToList();
            for (int i = 0; i < inputData.Count(); i++) { gammaBytes[i] ^= gamma[i]; }
            return gammaBytes;
        }
        #endregion
    }
}