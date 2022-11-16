
namespace Cipher.Cipher_Algorithms
{
    public interface ICipherBlockAlgorithm
    {
        public IEnumerable<byte> EncodeECB(List<byte> inputData, List<byte> key);
        public IEnumerable<byte> DecodeECB(List<byte> inputData, List<byte> key);

        public IEnumerable<byte> EncodeCBC(List<byte> inputData, List<byte> key, int intVec);
        public IEnumerable<byte> DecodeCBC(List<byte> inputData, List<byte> key, int intVec);

        public IEnumerable<byte> EncodeGammingCBE(List<byte> inputData, List<byte> key, int initVector);
        public IEnumerable<byte> DecodeGammingCBE(List<byte> inputData, List<byte> key, int initVector);
    }
}
