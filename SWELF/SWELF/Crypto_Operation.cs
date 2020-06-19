//Written by Ceramicskate0
//Copyright 2020
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using static System.Text.Encoding;

namespace SWELF
{
    internal static class Crypto_Operation
    {
        private const int AES256KeySize = 256;
        internal readonly static char[] Common_Encrypted_Chars = { '�','ó','�', '¿', 'ړ', '©', '°', '¤', 'ʔ','¶','»','ø','6','ځ','ª','Û','»','®' };

        private static byte[] Entropy = {System.Convert.ToByte(Settings.ComputerName.Length) };

        private static string SALT = Hash(Environment.ProcessorCount.ToString()).Substring(0,8);

        private static List <string> Cipher_Parts = new List<string>
        { Settings.ComputerName, SALT, Environment.UserName, Environment.UserDomainName, System.DirectoryServices.AccountManagement.UserPrincipal.Current.Sid.Value,  File_Operation.GET_CreationTime(File_Operation.Disk.RootDirectory+@"Windows\System32\config\SAM").ToString() };

        private static List<int> Cipher = new List<int>(Cipher_Parts.Count);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Performance", "CA1804:RemoveUnusedLocals", MessageId = "e")]
        internal static void Secure_File(string FilePath)
        {
            try
            {  
                File.Encrypt(FilePath);
                if (File_Operation.CHECK_File_Encrypted(FilePath)==false)
                {
                    Encrypt_File_Contents(FilePath);
                }
            }
            catch (Exception e)
            {
                File.Decrypt(FilePath);
            }
        }

        internal static void UnSecure_File(string FilePath, int RetryNumber = 0)
        {
            try
            {
                if (File_Operation.CHECK_File_Encrypted(FilePath)==true)
                {
                    File.AppendAllText(FilePath, Decrypt_File_Contents(FilePath));
                }
                File.Decrypt(FilePath);
            }
            catch (Exception e)
            {
                if (RetryNumber == 0)
                {
                    if (e.Message.ToString().Contains("The input data is not a complete block."))
                    {
                        Encrypt_File_Contents(FilePath);
                        File.Encrypt(FilePath);
                        UnSecure_File(FilePath, 1);
                    }
                    else
                    {
                        File.Decrypt(FilePath);
                    }
                }
                else if (e.Message.Contains("The input data is not a complete block."))
                {
                    if (FilePath.Contains(Settings.AppConfigFile_FileName) && Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents))
                    {
                        File.WriteAllText(Settings.GET_AppConfigFile_Path, Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.ConsoleAppConfig_Contents));
                    }
                    else if (FilePath.Contains(Settings.SearchTermsFileName_FileName) && Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.SearchTerms_File_Contents))
                    {
                        File.WriteAllText(Settings.GET_AppConfigFile_Path, Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.SearchTerms_File_Contents));
                    }
                    else
                    {
                        //error is logic
                    }
                }
                else
                {
                    Error_Operation.Log_Error("UnLock_File()", e.Message.ToString() + " "+ FilePath+ "  retry=" + RetryNumber,"", Error_Operation.LogSeverity.FailureAudit);
                }
            }
        }

        internal static void Encrypt_File_Contents(string InputFilePath)
        {
            byte[] encrypted;

            using (Aes AES = Aes.Create())
            {
                AES.KeySize = AES256KeySize;
                AES.BlockSize = 128;
                AES.Padding = PaddingMode.PKCS7;

                var key = new Rfc2898DeriveBytes(CONVERT_To_UTF8_Bytes(GET_Password()), CONVERT_To_UTF8_Bytes(SALT), 50000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                ICryptoTransform encryptor = AES.CreateEncryptor(AES.Key, AES.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(File.ReadAllText(InputFilePath));
                        }
                        encrypted = msEncrypt.ToArray();    
                    }
                }
                File_Operation.Turnicate_File(InputFilePath, encrypted);
            }
        }

        internal static string Decrypt_File_Contents(string InputEncryptedFilePath,bool ReWriteDecryptedFile=true)
        {
            string plaintext = null;
            CryptoStream csDecrypt = null;
            try
            {
                using (Aes AES = Aes.Create())
                {
                    AES.KeySize = AES256KeySize;
                    AES.BlockSize = 128;
                    AES.Padding = PaddingMode.PKCS7;

                    var key = new Rfc2898DeriveBytes(CONVERT_To_UTF8_Bytes(GET_Password()), CONVERT_To_UTF8_Bytes(SALT), 50000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    ICryptoTransform decryptor = AES.CreateDecryptor(AES.Key, AES.IV);

                    using (MemoryStream msDecrypt = new MemoryStream(File.ReadAllBytes(InputEncryptedFilePath)))
                    {
                        using (csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                            {
                                try
                                {
                                    plaintext = srDecrypt.ReadToEnd();
                                }
                                catch (Exception e)
                                {
                                    File_Operation.DELETE_File(InputEncryptedFilePath);
                                    File_Operation.WRITE_Default_Critical_Files();
                                }
                            }
                            csDecrypt = null;
                        }
                    }
                }
                if (ReWriteDecryptedFile)
                {
                    File_Operation.Turnicate_File(InputEncryptedFilePath);
                }
            }
            finally
            {
                if (csDecrypt != null)
                    csDecrypt.Dispose();
            }
            return plaintext;
        }

        internal static byte[] CONVERT_To_UTF8_Bytes(string String_Data)
        {
            return Encoding.UTF8.GetBytes(String_Data);
        }

        internal static byte[] CONVERT_To_ASCII_Bytes(string String_Data)
        {
            return Encoding.ASCII.GetBytes(String_Data);
        }

        internal static byte[] CONVERT_To_Default_Bytes(string String_Data)
        {
            return Encoding.Default.GetBytes(String_Data);
        }

        /// <summary>
        /// Charset
        /// 1=Default
        /// 2=UTF8
        /// 3=ASCII
        /// </summary>
        /// <param name="ByteData"></param>
        /// <param name="CharSet"></param>
        /// <returns></returns>
        internal static string CONVERT_To_String_From_Bytes(byte[] ByteData,int CharSet)
        {
            switch (CharSet)
                {
                case 1:
                    {
                        return Encoding.Default.GetString(ByteData);
                    }
                case 2:
                    {
                        return Encoding.UTF8.GetString(ByteData);
                    }
                case 3:
                    {
                        return Encoding.ASCII.GetString(ByteData);
                    }
                default:
                    {
                        return Encoding.Default.GetString(ByteData);
                    }
                }
        }

        internal static byte[] Protect_Data_Value(byte[] UnEncrypted_Value)
        {
            try
            {
                return ProtectedData.Protect(CONVERT_To_UTF8_Bytes(CONVERT_To_String_From_Bytes(UnEncrypted_Value,2)), Entropy, DataProtectionScope.CurrentUser);
            }
            catch (Exception e)
            {
                return new byte[0];
            }
        }

        internal static byte[] Protect_Data_Value(string UnEncrypted_Value)
        {
            try
            {
                return ProtectedData.Protect(CONVERT_To_UTF8_Bytes(UnEncrypted_Value), Entropy, DataProtectionScope.CurrentUser);
            }
            catch (Exception e)
            {
                return new byte[0]; 
            }
        }

        internal static string UnProtect_Data_Value(byte[] Encrypted_Value)
        {
            try
            {
                return CONVERT_To_String_From_Bytes(ProtectedData.Unprotect(Encoding.Default.GetBytes(CONVERT_To_String_From_Bytes(Encrypted_Value,1)), Entropy, DataProtectionScope.CurrentUser),1);
            }
            catch (Exception e)
            {
                return null;
            }
        }

        internal static string Protect_Memory(string UnEncrypted_Value)
        {
            byte[] toEncrypt = UnEncrypted_Value.ToByteArrayWithPadding();
            try
            {
                ProtectedMemory.Protect(toEncrypt, MemoryProtectionScope.SameProcess);
                return ASCII.GetString(toEncrypt);
            }
            catch (Exception e)
            {
                return ASCII.GetString(toEncrypt);
            }
        }

        internal static byte[] Protect_Memory(byte[] UnEncrypted_Value)
        {
            byte[] toEncrypt = ASCII.GetString(UnEncrypted_Value).ToByteArrayWithPadding();
            try
            {
                ProtectedMemory.Protect(toEncrypt, MemoryProtectionScope.SameProcess);
                return toEncrypt;
            }
            catch (Exception e)
            {
                return toEncrypt;
            }
        }

        //https://github.com/vunvulear/Stuff/blob/master/MemoryEncryption/MemoryEncryption.cs
        internal static string UnProtect_Memory(string Encrypted_Value)
        {
            byte[] byteEncrypted_Value = ASCII.GetBytes(Encrypted_Value.RemovePadding());
            try
            {
            ProtectedMemory.Unprotect(byteEncrypted_Value, MemoryProtectionScope.SameProcess);
            return ASCII.GetString(byteEncrypted_Value);
            }
            catch (Exception e)
            {
                return "";
            }
        }

        internal static string UnProtect_Memory(byte[] Encrypted_Value)
        {
            byte[] byteEncrypted_Value = ASCII.GetBytes(ASCII.GetString(Encrypted_Value).RemovePadding());
            try
            {
                ProtectedMemory.Unprotect(byteEncrypted_Value, MemoryProtectionScope.SameProcess);
                return ASCII.GetString(byteEncrypted_Value);
            }
            catch (Exception e)
            {
                return "";
            }
        }

        internal static byte[] ToByteArrayWithPadding(this String str)
        {
            const int BlockingSize = 16;
            int byteLength = ((str.Length / BlockingSize) + 1) * BlockingSize;
            byte[] toEncrypt = new byte[byteLength];
            ASCII.GetBytes(str).CopyTo(toEncrypt, 0);
            return toEncrypt;
        }

        internal static string RemovePadding(this String str)
        {
            char paddingChar = '\0';
            int indexOfFirstPadding = str.IndexOf(paddingChar);
            string cleanString="";
            if (indexOfFirstPadding > 0)
            {
                cleanString = str.Remove(indexOfFirstPadding);
            }
            else
            {
                cleanString = str;
            }
            return cleanString;
        }

        private static byte[] CreateRandomEntropy()
        {
            byte[] entropy = new byte[16];

            new RNGCryptoServiceProvider().GetBytes(entropy);

            return entropy;
        }

        private static void Padd(ref byte[] src_array, int pad_size)
        {
           Array.Resize(ref src_array, (src_array.Length + pad_size - 1) / pad_size * pad_size);
        }

        internal static void Clear_Password()
        {
            GCHandle gch = GCHandle.Alloc(GET_Password(), GCHandleType.Pinned);
            ZeroMemory(gch.AddrOfPinnedObject(), GET_Password().Length * 2);
            gch.Free();
        }

        internal static string Generate_Decrypt()
        {
            Random ran = new Random(Environment.TickCount);
            bool done = false;
            string key = "";
            char[] split = { ',' };
            int temp = ran.Next(0, Cipher_Parts.Count - 1);
            List<string> tmpList = new List<string>();

            while (!done)
            {
                if (key.Contains(temp.ToString())==true)
                {
                    temp=ran.Next(0, Cipher_Parts.Count);
                    done = false;
                }
                else
                {
                    key += temp.ToString()+',';
                    tmpList = key.Split(split, StringSplitOptions.RemoveEmptyEntries).Distinct().ToList();
                    Cipher = tmpList.Select(int.Parse).ToList();
                }

                if (Cipher_Parts.Count==Cipher.Count)
                {
                    done = true;
                }
            }
            return (key.Substring(0,key.Count()-1));
        }

        internal static string Hash(string Value)
        {
            var sha256 = SHA256.Create();
            try
            {
                if (File_Operation.CHECK_if_File_Exists(Value))
                {
                    return (BitConverter.ToString(sha256.ComputeHash(CONVERT_To_ASCII_Bytes(Value))));
                }
                else
                {
                    return (BitConverter.ToString(sha256.ComputeHash(CONVERT_To_ASCII_Bytes(Value))));
                }
            }
            catch (Exception e)
            {
                return (BitConverter.ToString(sha256.ComputeHash(CONVERT_To_ASCII_Bytes(Value))));
            }
        }

        private static string GET_Password()
        {
            if (Reg_Operation.CHECK_SWELF_Reg_Key_Exists(Reg_Operation.REG_KEY.Encryption)==false)
            {
                if (string.IsNullOrEmpty(Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.Encryption,false))==true)
                {
                   Reg_Operation.BASE_SWELF_KEY.SetValue(Reg_Operation.SWELF_Keys[(int)Reg_Operation.REG_KEY.Encryption].ToString(), Protect_Data_Value(Generate_Decrypt()));
                }
                else
                {
                    Settings.WRITE_Default_Configs_Files_and_Reg();
                }
            }
           string password = (Reg_Operation.READ_SWELF_Reg_Key(Reg_Operation.REG_KEY.Encryption));
           string content = "";
           string[] PWarray = (password).Split(',').ToArray();
            for (int x=0;x < PWarray.Length; ++x)
            {
                content += (Cipher_Parts.ElementAt(System.Convert.ToInt32(PWarray[x])));
            }
           return (Hash(content));
        }

        internal static bool CHECK_Value_Encrypted(string Value)
        {
            if ((Value.Any(s => Common_Encrypted_Chars.Contains(s)) && Value.Any(s => s < 128)))
            {
                return true;//Value Encrypted
            }
            else
            {
                return false;//Value NOT Encrypted
            }
        }

        internal static bool CHECK_Value_Encrypted(byte[] Value)
        {
            string ValueString = CONVERT_To_String_From_Bytes(Value,2);
            if ((ValueString.Any(s => Common_Encrypted_Chars.Contains(s)) && Value.Any(s => s < 128)))
            {
                return true;//Value Encrypted
            }
            else
            {
                return false;//Value NOT Encrypted
            }
        }

        [DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
        private static extern bool ZeroMemory(IntPtr Destination, int Length);

        internal static byte[] ObjectToByteArray(object obj)
        {
            BinaryFormatter bf = new BinaryFormatter();
            using (var ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                return ms.ToArray();
            }
        }

    }
}
