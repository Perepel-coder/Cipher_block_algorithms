
using Mathematics;

namespace Cipher.Cipher_Tools
{
    public class Word
    {
        public byte Byte1 { get; set; }
        public byte Byte2 { get; set; }
        public byte Byte3 { get; set; }
        public byte Byte4 { get; set; }

        #region Конструкторы
        public Word()
        {
            this.Byte1 = 0x00;
            this.Byte2 = 0x00;
            this.Byte3 = 0x00;
            this.Byte4 = 0x00;
        }
        public Word(byte b)
        {
            Byte1 = b;
            Byte2 = b;
            Byte3 = b;
            Byte4 = b;
        }
        public Word(byte b1, byte b2, byte b3, byte b4)
        {
            Byte1 = b1;
            Byte2 = b2;
            Byte3 = b3;
            Byte4 = b4;
        }
        public Word(IEnumerable<byte> array, int i)
        {
            List<byte> arr = new(array);
            Byte1 = arr[i];
            Byte2 = arr[i+1];
            Byte3 = arr[i+2];
            Byte4 = arr[i+3];
        }
        public Word(string str, int i)
        {
            Byte1 = (byte)str[i];
            Byte2 = (byte)str[i+1];
            Byte3 = (byte)str[i+2];
            Byte4 = (byte)str[i+3];
        }
        public Word(Word word)
        {
            Byte1 = word.Byte1;
            Byte2 = word.Byte2;
            Byte3 = word.Byte3;
            Byte4 = word.Byte4;
        }
        #endregion

        #region Замена байтов в слове
        public static byte SubBytes(byte myByte)
        {
            int[,] matrix = new int[,]
            {
                {1, 0, 0, 0, 1, 1, 1, 1 },
                {1, 1, 0, 0, 0, 1, 1, 1 },
                {1, 1, 1, 0, 0, 0, 1, 1 },
                {1, 1, 1, 1, 0, 0, 0, 1 },
                {1, 1, 1, 1, 1, 0, 0, 0 },
                {0, 1, 1, 1, 1, 1, 0, 0 },
                {0, 0, 1, 1, 1, 1, 1, 0 },
                {0, 0, 0, 1, 1, 1, 1, 1 }
            };
            int b = MathematicsGF.InversionPolynomialGF(myByte, 283);
            int[,] c = MathematicsGF.MultOfMatrixGF(matrix, MathematicsGF.CreatBITMatrixFromPoly(b, 8), 7);
            int[,] d = MathematicsGF.XorMatrix(c, MathematicsGF.CreatBITMatrixFromPoly(0x63, 8));
            byte result = (byte)MathematicsGF.CreatPolyFromBITMatrix(d);
            return result;
        }
        public static byte InvSubBytes(byte myByte)
        {
            int[,] matrix = new int[,]
            {
                {0, 0, 1, 0, 0, 1, 0, 1 },
                {1, 0, 0, 1, 0, 0, 1, 0 },
                {0, 1, 0, 0, 1, 0, 0, 1 },
                {1, 0, 1, 0, 0, 1, 0, 0 },
                {0, 1, 0, 1, 0, 0, 1, 0 },
                {0, 0, 1, 0, 1, 0, 0, 1 },
                {1, 0, 0, 1, 0, 1, 0, 0 },
                {0, 1, 0, 0, 1, 0, 1, 0 }
            };
            int[,] c = MathematicsGF.XorMatrix(MathematicsGF.CreatBITMatrixFromPoly(myByte, 8), MathematicsGF.CreatBITMatrixFromPoly(0x63, 8));
            int[,] b = MathematicsGF.MultOfMatrixGF(matrix, c, 7);
            byte result = (byte)MathematicsGF.InversionPolynomialGF(MathematicsGF.CreatPolyFromBITMatrix(b), 283);
            return result;
        }

        public Word SubWord()
        {
            return new()
            {
                Byte1 = SubBytes(this.Byte1),
                Byte2 = SubBytes(this.Byte2),
                Byte3 = SubBytes(this.Byte3),
                Byte4 = SubBytes(this.Byte4)
            };
        }
        public Word InvSubWord()
        {
            return new()
            {
                Byte1 = InvSubBytes(this.Byte1),
                Byte2 = InvSubBytes(this.Byte2),
                Byte3 = InvSubBytes(this.Byte3),
                Byte4 = InvSubBytes(this.Byte4)
            };
        }
        #endregion

        #region Сдвиг байтов в слове
        public Word RotWordLeft()
        {
            return new()
            {
                Byte1 = this.Byte2,
                Byte2 = this.Byte3,
                Byte3 = this.Byte4,
                Byte4 = this.Byte1
            };
        }
        public Word RotWordRight()
        {
            return new()
            {
                Byte1 = this.Byte4,
                Byte2 = this.Byte1,
                Byte3 = this.Byte2,
                Byte4 = this.Byte3
            };
        }
        #endregion

        public Word XOR(Word word2)
        {
            return new Word
            {
                Byte1 = (byte)(this.Byte1 ^ word2.Byte1),
                Byte2 = (byte)(this.Byte2 ^ word2.Byte2),
                Byte3 = (byte)(this.Byte3 ^ word2.Byte3),
                Byte4 = (byte)(this.Byte4 ^ word2.Byte4)
            };
        }
        public Word MultGF(Word word, long modPoly)
        {
            long word1 = Convert.ToUInt32(this.GetStringView16(), 16);
            long word2 = Convert.ToUInt32(word.GetStringView16(), 16);

            long multOfPolyGF = MathematicsGF.MultOfPolyGF(word1, word2, modPoly);

            string result = Convert.ToString(multOfPolyGF, 16);
            while (result.Length < 8) { result = Convert.ToString(0) + result; }
            return new()
            {
                Byte1 = Convert.ToByte(result[0..2], 16),
                Byte2 = Convert.ToByte(result[2..4], 16),
                Byte3 = Convert.ToByte(result[4..6], 16),
                Byte4 = Convert.ToByte(result[6..8], 16)
            };
        }
        public Word MultGF(long myByte, long modPoly)
        {
            long word1 = Convert.ToUInt32(this.GetStringView16(), 16);

            long multOfPolyGF = MathematicsGF.MultOfPolyGF(word1, myByte, modPoly);

            string result = Convert.ToString(multOfPolyGF, 16);
            while (result.Length < 8) { result = Convert.ToString(0) + result; }
            return new()
            {
                Byte1 = Convert.ToByte(result[0..2], 16),
                Byte2 = Convert.ToByte(result[2..4], 16),
                Byte3 = Convert.ToByte(result[4..6], 16),
                Byte4 = Convert.ToByte(result[6..8], 16)
            };
        }

        public byte[] GetArrayByte()
        {
            return new byte[4]
            {
                this.Byte1,
                this.Byte2,
                this.Byte3,
                this.Byte4
            };
        }

        public string GetStringView16()
        {
            static string Step(byte myByte) 
            {
                string resultByte = Convert.ToString(myByte, 16);
                while (resultByte.Length < 2) { resultByte = "0" + resultByte; }
                return resultByte;
            }
            string result = Step(this.Byte1) + Step(this.Byte2) + Step(this.Byte3) + Step(this.Byte4);
            return result;
        }
        public long GetLongView32()
        {
            return Convert.ToUInt32(this.GetStringView16(), 16);
        }
        public string GetStringView2()
        {
            static string Step(byte myByte)
            {
                string resultByte = Convert.ToString(myByte, 2);
                while (resultByte.Length < 8) { resultByte = "0" + resultByte; }
                return resultByte;
            }
            string result = Step(this.Byte1) + Step(this.Byte2) + Step(this.Byte3) + Step(this.Byte4);
            return result;
        }
        public override bool Equals(object? obj)
        {
            Word word = (Word)obj;
            if (this.Byte1 == word.Byte1 &&
                this.Byte2 == word.Byte2 &&
                this.Byte3 == word.Byte3 &&
                this.Byte4 == word.Byte4)
            {
                return true;
            }
            return false;
        }
    }
}
