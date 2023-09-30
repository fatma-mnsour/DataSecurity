using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data;
using System.Data.Common;
using System.Xml.Linq;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //  throw new NotImplementedException();
            string my_key = "";
            char[] Key = new char[26];

            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            string chars = "abcdefghijklmnopqrstuvwxyz";


            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < chars.Length; j++)
                {
                    if (plainText[i] == chars[j])
                    {
                        Key[j] = cipherText[i];
                        break;
                    }
                    else
                    {
                        continue;
                    }

                }

            }

            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < chars.Length; j++)
                {
                    if (cipherText[i] == chars[j])
                    {
                        chars = chars.Remove(j, 1);
                        break;
                    }
                    else
                    {
                        continue;
                    }

                }

            }
            int k = 0;
            for (int i = 0; i < 26; i++)
            {
                if (Key[i] == '\0')
                {
                    Key[i] = chars[k++];
                }
                else
                {
                    continue;
                }

            }

            for (int i = 0; i < 26; i++)
            {
                my_key += Key[i];
                continue;
            }
            Console.WriteLine(my_key);
            return my_key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plaintext = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                int j;
                for (j = 0; j < key.Length; j++)
                {
                    if ((char)(cipherText[i] + 32) == key[j])
                        break;
                }
                plaintext = plaintext + (char)(j + 'a');
            }
            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            char[] cipher = new char[plainText.Length];
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == ' ')
                { cipher[i] = ' '; }
                else
                {
                    int j = plainText[i] - 97;
                    cipher[i] = key[j];
                }
            }
            return new string(cipher);

        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            // throw new NotImplementedException();
            string alphabets = "ETAOINSRHLDCUMFPGWYBVKXJQZ".ToLower();
            string plainText = "";
            int c = 0;
            cipher = cipher.ToLower();

            Dictionary<char, int> cAlFreq = new Dictionary<char, int>();//dictionary to calculate the frequancy of letters

            //fill the first dictionary
            for (int i = 0; i < cipher.Length; i++)
            {
                if (!cAlFreq.ContainsKey(cipher[i]))
                {
                    cAlFreq.Add(cipher[i], 0);
                }
                else
                {
                    cAlFreq[cipher[i]]++;
                }
            }
            //sort elements
            cAlFreq = cAlFreq.OrderBy(y => y.Value).Reverse()
                .ToDictionary(y => y.Key, y => y.Value);


            SortedDictionary<char, char> plainTable = new SortedDictionary<char, char>();//dictionary to get the plane text

            //replace sorted letters based on the frequency
            foreach (var element in cAlFreq)
            {
                plainTable.Add(element.Key, alphabets[c]);
                c++;
            }

            //assign the replaced values into plainText string
            int j = 0;
            while (j < cipher.Length)
            {
                plainText += plainTable[cipher[j]];
                j++;
            }

            return (plainText);
        }
    }
}