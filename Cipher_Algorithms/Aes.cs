using Cipher.Cipher_Tools;
using Mathematics;

namespace Cipher.Cipher_Algorithms
{
    public class Aes : ICipherBlockAlgorithm
    {
        private readonly int numWBlock;        // кол-во слов в блоке
        private readonly int numWKey;          // кол-во слов в ключе
        private readonly int numBWord;         // кол-во байт в слове (длина слова)
        private readonly int numRound;         // кол-во раундов
        private readonly char defaultChar;     // дополняющий символ

        public Aes(int NumberWordkey, int NumberWordBlock, char defaultChar)
        {
            this.numWBlock = NumberWordBlock;
            this.numWKey = NumberWordkey;
            this.numBWord = 4;
            this.defaultChar = defaultChar;
            switch (NumberWordkey)
            {
                case 4: this.numRound = 10; break;
                case 6: this.numRound = 12; break;
                case 8: this.numRound = 16; break;
                default: throw new Exception("Не возможно применить заданные параметры ключа (длина)");
            }
        }

        /// <summary>
        /// Вычисление раундных ключей для всех раундов
        /// </summary>
        private List<Word[]> ExpandKey(List<byte> key)
        {
            List<Word> NewKey = new();
            int counter = this.numWBlock * (this.numRound + 1);
            while (key.Count % (this.numWKey * this.numBWord) != 0) { key.Add((byte)defaultChar); }
            for (int i = 0; i < key.Count; i += 4)
            {
                NewKey.Add(new Word(key, i));
            }
            for (int i = this.numWKey; i < counter; i++)
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
            List<Word[]> result = new();
            int numbOfBlock = NewKey.Count / this.numWBlock;
            for (int i = 0, x = 0; i < numbOfBlock; i++)
            {
                result.Add(new Word[this.numWBlock]);
                for (int j = 0; j < this.numWBlock; j++, x++) { result[i][j] = NewKey[x]; }
            }
            for (int i = this.numRound + 1; i < result.Count - 1; i++)
            {
                result[i] = XorBlocks(result[i], result[i + 1], this.numWBlock);
            }
            return (result.ToArray())[0..(this.numRound + 1)].ToList();
        }

        /// <summary>
        /// Сложение раундового ключа с блоком
        /// </summary>
        /// <param name="currentKey"> ключ текущего раунда </param>
        private static void AddRoundKey(List<Word> currentKey, Word[] block)
        {
            for (int i = 0; i < block.Length; i++)
            {
                block[i] = block[i].XOR(currentKey[i]);
            }
        }

        /// <summary>
        /// Сложение по модулю двух блоков
        /// </summary>
        /// <param name="block1"></param>
        /// <param name="block2"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        private static Word[] XorBlocks(Word[] block1, Word[] block2, int size)
        {
            Word[] result = new Word[size];
            for (int i = 0; i < size; i++)
            {
                result[i] = block1[i].XOR(block2[i]);
            }
            return result;
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

        #region Шифрование
        /// <summary>
        /// Подстановка байтов с помощью таблицы подстановок
        /// </summary>
        private static void SubBytes(Word[] block)
        {
            for (int i = 0; i < block.Length; i++)
            {
                block[i] = block[i].SubWord();
            }
        }

        /// <summary>
        /// Циклический сдвиг строк в форме на различные величины;
        /// </summary>
        private void ShiftRows(Word[] block)
        {
            int num = this.numWBlock - this.numBWord;
            Word[] newBlock = new Word[this.numWBlock];
            for (int i = 0; i <= num; i++)
            {
                newBlock[i] = new(block[i].Byte1, block[i + 1].Byte2, block[i + 2].Byte3, block[i + 3].Byte4);
            }
            num++;
            newBlock[num] = new(block[num].Byte1, block[num + 1].Byte2, block[num + 2].Byte3, block[0].Byte4); num++;
            newBlock[num] = new(block[num].Byte1, block[num + 1].Byte2, block[0].Byte3, block[1].Byte4); num++;
            newBlock[num] = new(block[num].Byte1, block[0].Byte2, block[1].Byte3, block[2].Byte4);

            for (int i = 0; i < block.Length; i++) { block[i] = newBlock[i]; }
        }

        /// <summary>
        /// Смешивание данных внутри каждого столбца формы
        /// </summary>
        private static void MixColumns(Word[] block)
        {
            int[,] matrix = new int[,]
            {
                { 0x02, 0x03, 0x01, 0x01 },
                { 0x01, 0x02, 0x03, 0x01 },
                { 0x01, 0x01, 0x02, 0x03 },
                { 0x03, 0x01, 0x01, 0x02 }
            };
            foreach (Word word in block)
            {
                int[,] matrixWord = new int[,]
                {
                        {word.Byte1 }, {word.Byte2 }, {word.Byte3 }, {word.Byte4 }
                };
                matrixWord = MathematicsGF.MultOfMatrixGF(matrix, matrixWord, 283);
                word.Byte1 = (byte)matrixWord[0, 0];
                word.Byte2 = (byte)matrixWord[1, 0];
                word.Byte3 = (byte)matrixWord[2, 0];
                word.Byte4 = (byte)matrixWord[3, 0];
            }
        }
        #endregion

        #region Дешифрование
        /// <summary>
        /// Подстановка байтов с помощью таблицы подстановок
        /// </summary>
        private static void InvSubBytes(Word[] block)
        {
            for (int i = 0; i < block.Length; i++)
            {
                block[i] = block[i].InvSubWord();
            }
        }

        /// <summary>
        /// Циклический сдвиг строк в форме на различные величины;
        /// </summary>
        private void InvShiftRows(Word[] block)
        {
            int size = this.numWBlock - 1;
            Word[] newBlock = new Word[this.numWBlock];
            newBlock[0] = new(block[0].Byte1, block[size].Byte2, block[size - 1].Byte3, block[size - 2].Byte4);
            newBlock[1] = new(block[1].Byte1, block[0].Byte2, block[size].Byte3, block[size - 1].Byte4);
            newBlock[2] = new(block[2].Byte1, block[1].Byte2, block[0].Byte3, block[size].Byte4);
            for (int i = 3; i < block.Length; i++)
            {
                newBlock[i] = new(block[i].Byte1, block[i - 1].Byte2, block[i - 2].Byte3, block[i - 3].Byte4);
            }
            for (int i = 0; i < block.Length; i++) { block[i] = newBlock[i]; }
        }

        /// <summary>
        /// Смешивание данных внутри каждого столбца формы
        /// </summary>
        private static void InvMixColumns(Word[] block)
        {
            int[,] matrix = new int[,]
            {
                { 0x0e, 0x0b, 0x0d, 0x09 },
                { 0x09, 0x0e, 0x0b, 0x0d },
                { 0x0d, 0x09, 0x0e, 0x0b },
                { 0x0b, 0x0d, 0x09, 0x0e }
            };
            foreach (Word word in block)
            {
                int[,] matrixWord = new int[,]
                {
                    {word.Byte1 }, {word.Byte2 }, {word.Byte3 }, {word.Byte4 }
                };
                matrixWord = MathematicsGF.MultOfMatrixGF(matrix, matrixWord, 283);
                word.Byte1 = (byte)matrixWord[0, 0];
                word.Byte2 = (byte)matrixWord[1, 0];
                word.Byte3 = (byte)matrixWord[2, 0];
                word.Byte4 = (byte)matrixWord[3, 0];
            }
        }
        #endregion

        #region Преобразование List<byte> в List<Word[]>
        private void GetWordsViewFromByte(int numOfBlocks, List<byte> inputData, List<Word[]> currentData)
        {
            while (inputData.Count % (numOfBlocks * this.numWBlock * this.numBWord) != 0) { inputData.Add((byte)defaultChar); }
            int j = 0;
            for (int i = 0; i < numOfBlocks; i++)
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

        private void EncodeBlock(Word[] block, List<Word[]> currentKey, int numRound)
        {

            for (int i = 0; i <= numRound - 2; i++)
            {
                Aes.AddRoundKey(currentKey[i].ToList(), block);
                Aes.SubBytes(block);
                this.ShiftRows(block);
                Aes.MixColumns(block);
            }

            Aes.AddRoundKey(currentKey[numRound - 1].ToList(), block);
            Aes.SubBytes(block);
            this.ShiftRows(block);

            Aes.AddRoundKey(currentKey[numRound].ToList(), block);
        }
        private void DecodeBlock(Word[] block, List<Word[]> currentKey, int numRound)
        {
            Aes.AddRoundKey(currentKey[numRound].ToList(), block);

            this.InvShiftRows(block);
            Aes.InvSubBytes(block);
            Aes.AddRoundKey(currentKey[numRound - 1].ToList(), block);

            for (int i = numRound - 2; i >= 0; i--)
            {
                Aes.InvMixColumns(block);
                this.InvShiftRows(block);
                Aes.InvSubBytes(block);
                Aes.AddRoundKey(currentKey[i].ToList(), block);
            }
        }


        #region Interface implementation ICipher

        /// <summary>
        /// Закодировать AES ECB режим
        /// </summary>
        /// <param name="inputData"> входные данные </param>
        /// <param name="key"> ключ </param>
        public IEnumerable<byte> EncodeECB(IEnumerable<byte> inputData, IEnumerable<byte> key)
        {
            List<Word[]> currentData = new();
            int numOfBlocks = inputData.Count() / (this.numWBlock * this.numBWord) + 1;
            this.GetWordsViewFromByte(numOfBlocks, inputData.ToList(), currentData);

            List<Word[]> currentKey = this.ExpandKey(key.ToList());
            for (int i = 0; i < currentData.Count; i++)
            {
                EncodeBlock(currentData[i], currentKey, this.numRound);
            }
            return this.GetResultData(currentData, true);
        }

        /// <summary>
        /// Раскодировать AES ECB режим
        /// </summary>
        /// <param name="inputData"> входные данные </param>
        /// <param name="key"> ключ </param>
        /// <returns> расшифровка </returns>
        /// <exception cref="Exception"></exception>
        public IEnumerable<byte> DecodeECB(IEnumerable<byte> inputData, IEnumerable<byte> key)
        {
            List<Word[]> currentData = new();
            int numOfBlocks = inputData.Count() / (this.numWBlock * this.numBWord);
            if (numOfBlocks == 0) { throw new Exception("Не корректные входные данные."); }
            this.GetWordsViewFromByte(numOfBlocks, inputData.ToList(), currentData);

            List<Word[]> currentKey = this.ExpandKey(key.ToList());
            for (int i = 0; i < currentData.Count; i++)
            {
                DecodeBlock(currentData[i], currentKey, this.numRound);
            }
            return this.GetResultData(currentData, false);
        }

        /// <summary>
        /// Закодировать AES CBC режим
        /// </summary>
        /// <param name="inputData"> входные данные </param>
        /// <param name="key"> входные данные </param>
        /// <param name="initVector"> управлябщий вектор </param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public IEnumerable<byte> EncodeCBC(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector)
        {
            List<Word[]> currentData = new();
            int numOfBlocks = inputData.Count() / (this.numWBlock * this.numBWord) + 1;
            this.GetWordsViewFromByte(numOfBlocks, inputData.ToList(), currentData);

            List<Word[]> vec = new();
            this.GetWordsViewFromByte(numOfBlocks, this.CreatInitVector(initVector, numOfBlocks), vec);
            List<Word[]> currentKey = this.ExpandKey(key.ToList());

            for (int i = 0; i < currentData.Count; i++)
            {
                if (i == 0) { currentData[0] = Aes.XorBlocks(vec[0].ToArray(), currentData[0], this.numWBlock); }
                else { currentData[i] = Aes.XorBlocks(currentData[i - 1], currentData[i], this.numWBlock); }
                EncodeBlock(currentData[i], currentKey, this.numRound);
            }
            return this.GetResultData(currentData, true);
        }

        /// <summary>
        ///  Раскодировать AES CBC режим
        /// </summary>
        /// <param name="inputData"> входные данные </param>
        /// <param name="key"> входные данные </param>
        /// <param name="intVec"> управлябщий вектор </param>
        /// <returns></returns>
        public IEnumerable<byte> DecodeCBC(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector)
        {
            List<Word[]> currentData = new();
            int numOfBlocks = inputData.Count() / (this.numWBlock * this.numBWord);
            if (numOfBlocks == 0) { throw new Exception("Не корректные входные данные."); }
            this.GetWordsViewFromByte(numOfBlocks, inputData.ToList(), currentData);

            List<Word[]> vec = new();
            this.GetWordsViewFromByte(numOfBlocks, this.CreatInitVector(initVector, numOfBlocks), vec);
            List<Word[]> currentKey = this.ExpandKey(key.ToList());
            List<Word[]> cipherData = new();
            foreach (var el in currentData)
            {
                Word[] block = new Word[this.numWBlock];
                Array.Copy(el, block, this.numWBlock);
                cipherData.Add(block);
            }

            for (int i = 0; i < currentData.Count; i++)
            {
                DecodeBlock(currentData[i], currentKey, this.numRound);
                if (i == 0) { currentData[0] = Aes.XorBlocks(vec[0].ToArray(), currentData[0], this.numWBlock); }
                else { currentData[i] = Aes.XorBlocks(cipherData[i - 1], currentData[i], this.numWBlock); }
            }
            return this.GetResultData(currentData, false);
        }

        public IEnumerable<byte> EncodeGammingECB(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector)
        {
            int numOfBlocks = inputData.Count() / (this.numWBlock * this.numBWord) + 1;
            List<Word[]> gammaWords = new();
            List<byte> gammaBytes = this.CreatInitVector(initVector, numOfBlocks);
            for (int i = 0; i < inputData.Count(); i++) { gammaBytes[i] ^= inputData.ToList()[i]; }
            this.GetWordsViewFromByte(numOfBlocks, gammaBytes, gammaWords);
            List<Word[]> currentKey = this.ExpandKey(key.ToList());
            for (int i = 0; i < gammaWords.Count; i++)
            {
                this.EncodeBlock(gammaWords[i], currentKey, this.numRound);
            }
            return this.GetResultData(gammaWords, true);
        }

        public IEnumerable<byte> DecodeGammingECB(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector)
        {
            List<Word[]> gammaWords = new();
            int numOfBlocks = inputData.Count() / (this.numWBlock * this.numBWord);
            if (numOfBlocks == 0) { throw new Exception("Не корректные входные данные."); }
            this.GetWordsViewFromByte(numOfBlocks, inputData.ToList(), gammaWords);
            List<Word[]> currentKey = this.ExpandKey(key.ToList());
            for (int i = 0; i < gammaWords.Count; i++)
            {
                this.DecodeBlock(gammaWords[i], currentKey, this.numRound);
            }
            List<byte> gamma = this.CreatInitVector(initVector, numOfBlocks);
            List<byte> gammaBytes = this.GetResultData(gammaWords, true).ToList();
            for (int i = 0; i < inputData.Count(); i++) { gammaBytes[i] ^= gamma[i]; }
            return gammaBytes;
        }

        #endregion
    }
}