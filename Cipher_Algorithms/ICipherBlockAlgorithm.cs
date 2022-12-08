
namespace Cipher.Cipher_Algorithms
{
    public interface ICipherBlockAlgorithm
    {
        public int BlockSize { get; }
        public IEnumerable<byte> EncodeECB(IEnumerable<byte> inputData, IEnumerable<byte> key);
        public IEnumerable<byte> DecodeECB(IEnumerable<byte> inputData, IEnumerable<byte> key);

        public IEnumerable<byte> EncodeCBC(IEnumerable<byte> inputData, IEnumerable<byte> key, int intVec);
        public IEnumerable<byte> DecodeCBC(IEnumerable<byte> inputData, IEnumerable<byte> key, int intVec);

        public IEnumerable<byte> EncodeGammingECB(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector);
        public IEnumerable<byte> DecodeGammingECB(IEnumerable<byte> inputData, IEnumerable<byte> key, int initVector);
    }
}
