using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            // throw new NotImplementedException();
            string encrypted = string.Empty;
            plainText = plainText.ToLower();
            string x = "abcdefghijklmnopqrstuvwxyz";

            //string index=new string x.ToArray();


            for (int j = 0; j < plainText.Length; j++)
            {

                for (int i = 0; i < x.Length; i++)
                {

                    if (plainText[j] == x[i])
                    {
                        char Enc = x[((i + key) % 26)];
                        encrypted += Enc;
                    }
                }
            }
            return encrypted;

        }

        public string Decrypt(string cipherText, int key)
        {
            //  throw new NotImplementedException();
            return Encrypt(cipherText, 26 - key);
        }

        public int Analyse(string plainText, string cipherText)
        {

            // throw new NotImplementedException();

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = ((cipherText[0] - 97 + 26) % 26) - (plainText[0] - 97);
            if (key < 0)
                key += 26;
            return key;

        }
    }
}
