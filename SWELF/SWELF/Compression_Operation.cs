//Written by Ceramicskate0
//Copyright 2020
using System;
using System.Text;
using System.IO;
using System.IO.Compression;


namespace SWELF
{
    internal class Compression_Operation
    {
        internal static UTF8Encoding utfEncode = new UTF8Encoding();

        internal static byte[] Compress_Contents_Byte(byte[] bytesToCompress)
        {
            using (MemoryStream memory = new MemoryStream(bytesToCompress))
            {
                using (DeflateStream compressionStream = new DeflateStream(memory, CompressionMode.Compress,false))
                {
                    compressionStream.Write(bytesToCompress, 0, bytesToCompress.Length);
                }
            }
            //Crypto_Operation.Protect_Memory(bytesToCompress);
            return (bytesToCompress);
        }

        internal static byte[] Compress_Contents_Byte(string ToCompress)
        {
            byte[] bytesToCompress = utfEncode.GetBytes(ToCompress);
            using (MemoryStream memory = new MemoryStream(bytesToCompress))
            {
                using (DeflateStream compressionStream = new DeflateStream(memory, CompressionMode.Compress,false))
                {
                    compressionStream.Write(bytesToCompress, 0, bytesToCompress.Length);
                }
            }
            //Crypto_Operation.Protect_Memory(bytesToCompress);
            return (bytesToCompress);
        }

        internal static string DeCompress_Contents_String(byte[] BytesToDecompress,int Size)
        {
            byte[] decompressedBytes = new byte[Size];
            //Crypto_Operation.UnProtect_Memory(decompressedBytes);
            using (MemoryStream memory = new MemoryStream(BytesToDecompress))
            {
                using (DeflateStream decompressionStream = new DeflateStream(memory, CompressionMode.Decompress,false))
                {
                    decompressionStream.Read(decompressedBytes, 0, Size);
                }
            }
            return (utfEncode.GetString(decompressedBytes));
        }
    }
}
