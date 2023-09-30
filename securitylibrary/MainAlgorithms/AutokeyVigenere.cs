using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string keystream = string.Empty;
            string key = string.Empty;
            string x = "abcdefghijklmnopqrstuvwxyz";
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                keystream += x[((cipherText[i] - plainText[i] + 26) % 97) % 26];
            }
            for (int i = 0; i < keystream.Length; i++)
            {
                if (keystream[i] == plainText[0] && keystream[i + 1] == plainText[1])
                {
                    key = keystream.Remove(i);


                }

            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            string x = "abcdefghijklmnopqrstuvwxyz";
            string decrypted = string.Empty;

            int diffrence = cipherText.Length - key.Length;


            for (int i = 0; i < diffrence; i++)
            {
                int p = ((x.IndexOf(cipherText[i]) - x.IndexOf(key[i])) + 26) % 26;
                key = key + x[p];


            }
            for (int i = 0; i < cipherText.Length; i++)
            {

                int d = ((x.IndexOf(cipherText[i]) - x.IndexOf(key[i])) + 26) % 26;
                decrypted += x[d];
            }
            return decrypted;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();

            plainText = plainText.ToLower();
            key = key.ToLower();
            string x = "abcdefghijklmnopqrstuvwxyz";
            string encrypted = string.Empty;


            for (int i = 0; i < plainText.Length; i++)
            {
                key = key + plainText[i];
            }


            for (int i = 0; i < plainText.Length; i++)
            {


                char c = x[((plainText[i] + key[i]) % 97) % 26];
                encrypted += c;


            }


            return encrypted;
        }
    }
}
