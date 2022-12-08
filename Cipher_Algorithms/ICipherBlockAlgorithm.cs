
namespace Cipher.Cipher_Algorithms
{
    public interface ICipherBlockAlgorithm
    {
        public int BlockSize { get; }
        public IEnumerable<byte> EncodeECB(IEnumerable<byte> inputData, IEnumerable<byte> key);
        public IEnumerable<byte> DecodeECB(IEnumerable<byte> inputData, IEnumerable<byte> key);

        public IEnumerable<byte> EncodeCBC(IEnumerable<byte> inputData, IEnumerable<byte> key, int intVec);
        public IEnumerable<byte> DecodeCBC(IEnumerable<byte> inputData, IEnumerable<byte> key, int intVec);

        public IEnumerable<byte> Gamming(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector);
    }
}
