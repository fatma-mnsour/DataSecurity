using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        byte[,] SBox = new byte[16, 16] {
      {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
      {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
      {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
      {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
      {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
      {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
      {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
      {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
      {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
      {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
      {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
      {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
      {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
      {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
      {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
      {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };

        byte[,] Rcon = new byte[4, 10] {
        {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}};

        public static string[,] Miacimis_col_array;
        public static string[,] array_shifted;
        public static int[,] xx;

        public override string Decrypt(string cipherText, string password)
        {
            string[] password_exp = new string[11];
            int[] pass = new int[20];
            password_exp[0] = password; for (int i = 0; i < 10; i++) password_exp[i + 1] = KeyExpansion(password_exp[i], i);
            string[,] plain = new string[4, 4];

            if (cipherText[1] == 'x' || cipherText[1] == 'X') cipherText = cipherText.Substring(2, 32);
            for (int h = 0, k = 0; h < 4; h++)
            {
                //count rate 2 increase
                for (int j = 0; j < 4; j++, k += 2)
                {
                    string candi = cipherText[k].ToString() + cipherText[k + 1];
                    plain[h, j] = candi;
                }
            }
            cipherText = AddRoundKey(plain, password_exp[10]);
            if (cipherText[1] != 'x' && cipherText[1] != 'X') cipherText = "0x" + cipherText;

            cipherText = InvShiftRows(cipherText);
            cipherText = InvSubBytes(cipherText);

            for (int i = 9; i > 0; i--)
            {
                if (cipherText[1] == 'x' || cipherText[1] == 'X') cipherText = cipherText.Substring(2, 32);
                //compare cipher text if equal x or sub
                for (int h = 0, k = 0; h < 4; h++)
                {
                    for (int j = 0; j < 4; j++, k += 2)
                    {
                        string c = cipherText[k].ToString() + cipherText[k + 1];
                        plain[h, j] = c;
                    }
                }
                cipherText = AddRoundKey(plain, password_exp[i]);
                if (cipherText[1] != 'x' && cipherText[1] != 'X') cipherText = "0x" + cipherText;
                cipherText = InvMixColumns(cipherText);
                cipherText = InvShiftRows(cipherText);
                cipherText = InvSubBytes(cipherText);
            }
            if (cipherText[1] == 'x' || cipherText[1] == 'X') cipherText = cipherText.Substring(2, 32);
            for (int h = 0, k = 0; h < 4; h++)
            {
                for (int j = 0; j < 4; j++, k += 2)
                {
                    string candi = cipherText[k].ToString() + cipherText[k + 1];
                    plain[h, j] = candi;
                }
            }
            for (int y = 1; y <= pass.Length; y += 2)
            {
                //string cipherText[y].string
            }
            cipherText = AddRoundKey(plain, password_exp[0]);
            return "0x" + cipherText;
        }

        public override string Encrypt(string text_of_plain, string key_of_CIPHER)
        {
            byte[,] Matrix_plain = StringToMatrixOfBytes(text_of_plain);
            byte[,] Matrix_key = StringToMatrixOfBytes(key_of_CIPHER);
            //Round 0
            Matrix_plain = AddRoundkey(Matrix_plain, Matrix_key);
            //Rounds 1 to 9
            for (int i = 1; i <= 9; i++)
            {
                Matrix_key = RoundKey(Matrix_key, i);
                Matrix_plain = AddRoundkey(MixCol(ShiftRows(SubByte(Matrix_plain))), Matrix_key);
            }
            //Round 10
            Matrix_key = RoundKey(Matrix_key, 10);
            Matrix_plain = AddRoundkey(ShiftRows(SubByte(Matrix_plain)), Matrix_key);

            return MatrixOfBytesToString(Matrix_plain);
        }

        private byte[,] StringToMatrixOfBytes(string hexStr)
        {
            //Remove"0x"
            hexStr = hexStr.Substring(2);

            //store the parsed values
            byte[] bytes = new byte[hexStr.Length / 2];

            //parse each byte
            for (int i = 0; i < hexStr.Length; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexStr.Substring(i, 2), 16);
            }

            //fill matrix with the parsed bytes
            byte[,] matrix = new byte[4, 4];
            int index = 0;
            for (int col = 0; col < 4; col++)
            {
                for (int row = 0; row < 4; row++)
                {
                    matrix[row, col] = bytes[index++];
                }
            }
            return matrix;
        }

        private byte[,] SubByte(byte[,] a_plain)
        {
            int i = 0;
            byte[,] SUB_bytes = new byte[4, 4];
            while (i < 4)
            {
                int j = 0;
                while (j < 4)
                {
                    int upper = (a_plain[i, j] >> 4) & 0x0f;
                    int lower = a_plain[i, j] & 0x0f;

                    SUB_bytes[i, j] = SBox[upper, lower];
                    j++;
                }
                i++;
            }

            return SUB_bytes;
        }
        private byte[,] AddRoundkey(byte[,] b_plain, byte[,] Key)
        {
            byte[,] bytes = new byte[4, 4];

            // iterate over the rows and columns of the input matrices simultaneously
            var query = from row in Enumerable.Range(0, 4)
                        from col in Enumerable.Range(0, 4)
                        select new { Row = row, Column = col };

            foreach (var i in query)
            {
                bytes[i.Column, i.Row] = (byte)((int)b_plain[i.Column, i.Row] ^ (int)Key[i.Column, i.Row]);
            }

            return bytes;
        }

        private byte[,] RoundKey(byte[,] Key, int rounds)
        {

            byte[,] bytes = new byte[4, 4];
            bytes[0, 0] = SBox[Key[1, 3] >> 4, Key[1, 3] & 0x0f];
            bytes[1, 0] = SBox[Key[2, 3] >> 4, Key[2, 3] & 0x0f];
            bytes[2, 0] = SBox[Key[3, 3] >> 4, Key[3, 3] & 0x0f];
            bytes[3, 0] = SBox[Key[0, 3] >> 4, Key[0, 3] & 0x0f];
            for (int i = 0; i < 4; i++)
            {
                bytes[i, 0] = (byte)((int)bytes[i, 0] ^ (int)Rcon[i, rounds - 1]);
                bytes[i, 0] = (byte)((int)bytes[i, 0] ^ (int)Key[i, 0]);
            }
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++) bytes[j, i] = (byte)((int)bytes[j, i - 1] ^ (int)Key[j, i]);
            }
            return bytes;
        }

        private byte[,] ShiftRows(byte[,] b_plain)
        {
            byte[,] Shift_bytes = new byte[4, 4];

            for (int i = 0; i < 4; i++)
            {
                // Shift the row to the left
                for (int j = 0; j < 4; j++)
                {
                    int shiftedIndex = (j + i) % 4;
                    Shift_bytes[i, j] = b_plain[i, shiftedIndex];
                }
            }

            return Shift_bytes;
        }

        private byte[,] MixCol(byte[,] b_plain)
        {
            byte[,] bytes = new byte[4, 4];
            for (int j = 0; j < 4; j++)
            {
                //temporary variables to hold the values of each row in the current column
                byte s0 = b_plain[0, j];
                byte s1 = b_plain[1, j];
                byte s2 = b_plain[2, j];
                byte s3 = b_plain[3, j];

                //MixCol transformation to the current column
                byte t0 = (byte)(GMul(0x02, s0) ^ GMul(0x03, s1) ^ s2 ^ s3);
                byte t1 = (byte)(s0 ^ GMul(0x02, s1) ^ GMul(0x03, s2) ^ s3);
                byte t2 = (byte)(s0 ^ s1 ^ GMul(0x02, s2) ^ GMul(0x03, s3));
                byte t3 = (byte)(GMul(0x03, s0) ^ s1 ^ s2 ^ GMul(0x02, s3));

                // Store the transformed values back into bytes
                bytes[0, j] = t0;
                bytes[1, j] = t1;
                bytes[2, j] = t2;
                bytes[3, j] = t3;
            }

            return bytes;
        }

        private static byte GMul(byte a, byte b)
        {
            byte[] powersOf2 = new byte[8];
            byte[] multFact = new byte[8];

            // Compute the powers of 2 and the multiplication factors
            powersOf2[0] = 1;
            multFact[0] = b;
            for (int i = 1; i < 8; i++)
            {
                powersOf2[i] = (byte)(powersOf2[i - 1] << 1);
                if ((multFact[i - 1] & 0x80) != 0)
                    multFact[i] = (byte)((multFact[i - 1] << 1) ^ 0x1b);
                else
                    multFact[i] = (byte)(multFact[i - 1] << 1);
            }

            // Compute the resultof a and b using the multiplication table
            byte result = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((a & powersOf2[i]) != 0)
                    result ^= multFact[i];
            }
            return result;
        }

        private string MatrixOfBytesToString(byte[,] bytes)
        {
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    hex.AppendFormat("{0:x2}", bytes[j, i]);
                }
            }
            return "0x" + hex.ToString();
        }

        static string KeyExpansion(string key, int round)
        {
            string[,] S__Box ={
            {"63","7c","77","7b","f2","6b","6f","c5","30","01","67","2b","fe","d7","ab","76"},
            {"ca","82","c9","7d","fa","59","47","f0","ad","d4","a2","af","9c","a4","72","c0"},
            {"b7","fd","93","26","36","3f","f7","cc","34","a5","e5","f1","71","d8","31","15"},
            {"04","c7","23","c3","18","96","05","9a","07","12","80","e2","eb","27","b2","75"},
            {"09","83","2c","1a","1b","6e","5a","a0","52","3b","d6","b3","29","e3","2f","84"},
            {"53","d1","00","ed","20","fc","b1","5b","6a","cb","be","39","4a","4c","58","cf"},
            {"d0","ef","aa","fb","43","4d","33","85","45","f9","02","7f","50","3c","9f","a8"},
            {"51","a3","40","8f","92","9d","38","f5","bc","b6","da","21","10","ff","f3","d2"},
            {"cd","0c","13","ec","5f","97","44","17","c4","a7","7e","3d","64","5d","19","73"},
            {"60","81","4f","dc","22","2a","90","88","46","ee","b8","14","de","5e","0b","db"},
            {"e0","32","3a","0a","49","06","24","5c","c2","d3","ac","62","91","95","e4","79"},
            {"e7","c8","37","6d","8d","d5","4e","a9","6c","56","f4","ea","65","7a","ae","08"},
            {"ba","78","25","2e","1c","a6","b4","c6","e8","dd","74","1f","4b","bd","8b","8a"},
            {"70","3e","b5","66","48","03","f6","0e","61","35","57","b9","86","c1","1d","9e"},
            {"e1","f8","98","11","69","d9","8e","94","9b","1e","87","e9","ce","55","28","df"},
            {"8c","a1","89","0d","bf","e6","42","68","41","99","2d","0f","b0","54","bb","16"}
            };
            string[,] R__Con =
            {
                { "01" , "02" , "04" , "08" , "10" , "20" , "40" , "80" , "1b" , "36"},
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" },
                { "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" , "00" }

            };
            string[,] newPassword = new string[4, 4];
            for (int i = 0, l = 2; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string s = key[l].ToString() + key[l + 1].ToString();
                    newPassword[j, i] = s;
                    l += 2;
                }
            }
            string[] tempKey = new string[4];
            for (int i = 0; i < 4; i++)
            {
                tempKey[i] = newPassword[i, 3];
            }
            tempKey = RotWord(tempKey);


            string rTemp = "";
            for (int i = 0; i < 4; i++)
            {
                rTemp += tempKey[i];
            }

            string subTemp = "";
            rTemp = rTemp.ToUpper();


            for (int i = 0; i < rTemp.Length; i += 2)
            {
                int ind1 = int.Parse(rTemp[i].ToString(), System.Globalization.NumberStyles.HexNumber);
                int ind2 = int.Parse(rTemp[i + 1].ToString(), System.Globalization.NumberStyles.HexNumber);

                subTemp += S__Box[ind1, ind2];
            }

            string[,] res_key = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                int ky = Convert.ToInt32(newPassword[i, 0], 16);
                int sub = Convert.ToInt32(subTemp.Substring(i * 2, 2), 16);
                int rcon = Convert.ToInt32(R__Con[i, round], 16);

                int x = ky ^ sub ^ rcon;
                string str = x.ToString("X2");
                res_key[i, 0] = str;
            }

            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    int resKey = Convert.ToInt32(res_key[j, i - 1], 16);
                    int ky = Convert.ToInt32(newPassword[j, i], 16);
                    int x = ky ^ resKey;
                    string str = Convert.ToString(x, 16);
                    if (x < 16) res_key[j, i] = "0" + str;
                    else res_key[j, i] = str;
                }
            }
            string ResKey = "0x";
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)


                    ResKey += res_key[j, i];

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                    Console.Write(res_key[i, j]);
                Console.WriteLine();
            }
            Console.WriteLine();
            return ResKey;
        }

        public static string AddRoundKey(string[,] plain, string key)
        {

            string plaintext = "";

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plaintext += plain[i, j];
                }
            }
            string result = "";

            for (int i = 0; i < plaintext.Length; i += 2)
            {
                int p = Convert.ToInt32(plaintext.Substring(i, 2), 16);
                int keyNumber = Convert.ToInt32(key.Substring(i + 2, 2), 16);
                int xr = p ^ keyNumber;
                string str = "";
                if (xr < 16) str = "0" + Convert.ToString(xr, 16);
                else str = Convert.ToString(xr, 16);
                result += str;
            }
            return result;
        }

        public static string[] RotWord(string[] word)
        {
            return new string[] { word[1], word[2], word[3], word[0] };
        }
        public static string InvSubBytes(string plain)
        {
            List<string> new_plain = new List<string>();
            List<string> sub_plain = new List<string>();
            int[] j = new int[10];
            string[,] sfexic_box ={
                {"52","09","6a","d5","30","36","a5","38","bf","40","a3","9e","81","f3","d7","fb"},
                {"7c","e3","39","82","9b","2f","ff","87","34","8e","43","44","c4","de","e9","cb"},
                {"54","7b","94","32","a6","c2","23","3d","ee","4c","95","0b","42","fa","c3","4e"},
                {"08","2e","a1","66","28","d9","24","b2","76","5b","a2","49","6d","8b","d1","25"},
                {"72","f8","f6","64","86","68","98","16","d4","a4","5c","cc","5d","65","b6","92"},
                {"6c","70","48","50","fd","ed","b9","da","5e","15","46","57","a7","8d","9d","84"},
                {"90","d8","ab","00","8c","bc","d3","0a","f7","e4","58","05","b8","b3","45","06"},
                {"d0","2c","1e","8f","ca","3f","0f","02","c1","af","bd","03","01","13","8a","6b"},
                {"3a","91","11","41","4f","67","dc","ea","97","f2","cf","ce","f0","b4","e6","73"},
                {"96","ac","74","22","e7","ad","35","85","e2","f9","37","e8","1c","75","df","6e"},
                {"47","f1","1a","71","1d","29","c5","89","6f","b7","62","0e","aa","18","be","1b"},
                {"fc","56","3e","4b","c6","d2","79","20","9a","db","c0","fe","78","cd","5a","f4"},
                {"1f","dd","a8","33","88","07","c7","31","b1","12","10","59","27","80","ec","5f"},
                {"60","51","7f","a9","19","b5","4a","0d","2d","e5","7a","9f","93","c9","9c","ef"},
                {"a0","e0","3b","4d","ae","2a","f5","b0","c8","eb","bb","3c","83","53","99","61"},
                {"17","2b","04","7e","ba","77","d6","26","e1","69","14","63","55","21","0c","7d"},
            };
            for (int i = 0; i < plain.Length; i++)
            {
                if (plain[i] == 'A' || plain[i] == 'a')
                    new_plain.Add("10");
                else if (plain[i] == 'B' || plain[i] == 'b')
                    new_plain.Add("11");
                else if (plain[i] == 'C' || plain[i] == 'c')
                    new_plain.Add("12");
                else if (plain[i] == 'D' || plain[i] == 'd')
                    new_plain.Add("13");
                else if (plain[i] == 'E' || plain[i] == 'e')
                    new_plain.Add("14");
                else if (plain[i] == 'F' || plain[i] == 'f')
                    new_plain.Add("15");
                else
                    new_plain.Add(plain[i].ToString());
            }

            for (int k = 2; k < new_plain.Count - 1; k += 2)
            {
                sub_plain.Add(sfexic_box[int.Parse(new_plain[k]), int.Parse(new_plain[k + 1])]);
            }
            string str = "0x";
            for (int i = 0; i < sub_plain.Count; i++)
            {
                str += sub_plain[i];
            }
            return str;
        }

        public static string InvShiftRows(string result)
        {
            string[,] temp = new string[4, 4];
            string[,] p = new string[4, 4];
            int count = 0;
            List<string> temp_list = new List<string>();
            string str = "";
            for (int i = 2; i < result.Length; i += 2)
            {
                str = result[i].ToString() + result[i + 1].ToString();
                temp_list.Add(str);
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {

                    p[j, i] = temp_list[count];
                    count++;
                }

            }

            for (int i = 0; i < 1; i++)
            {
                int j = 0;
                while (j < 4)
                {
                    temp[i, j] = p[i, j];
                    j++;
                }
            }


            string st = "0x";

            for (int t = 1; t < 4; ++t)
            {
                for (int l = 0; l < 4; ++l)
                {
                    temp[t, (l + t) % 4] = p[t, l];

                }
            }
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    st += temp[j, i];
                }
            }
            return st;
        }


        private static int Mul2(int b)
        {
            b = b << 1;
            if ((b & 256) != 0)
            {
                b -= 256;
                b ^= 27;
            }
            return b;

        }

        public static string HexToDec(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                throw new ArgumentException("Input cannot be null or empty");
            }

            // hexadecimal characters --> decimal digits
            Dictionary<char, int> hex = new Dictionary<char, int>() {
        { '0', 0 }, { '1', 1 }, { '2', 2 }, { '3', 3 },
        { '4', 4 }, { '5', 5 }, { '6', 6 }, { '7', 7 },
        { '8', 8 }, { '9', 9 }, { 'A', 10 }, { 'B', 11 },
        { 'C', 12 }, { 'D', 13 }, { 'E', 14 }, { 'F', 15 }
        };

            // hexadecimal string --> decimal integer
            int dec = 0;
            foreach (char c in value)
            {
                if (!hex.ContainsKey(Char.ToUpper(c)))
                {
                    throw new ArgumentException($"Invalid hexadecimal character '{c}'");
                }
                dec = dec * 16 + hex[Char.ToUpper(c)];
            }
            return dec.ToString();
        }

        public static string InvMixColumns(string res)
        {
            byte[] bytes = new byte[16];
            //bytes
            for (int i = 0; i < 16; i++)
            {
                bytes[i] = Convert.ToByte(res.Substring(2 + i * 2, 2), 16);
            }
            //inverse mix columns
            byte[] result = new byte[16];
            for (int i = 0; i < 4; i++)
            {
                int idx = i * 4;
                result[idx] = (byte)(gfmule(bytes[idx]) ^ gfmulb(bytes[idx + 1]) ^ gfmuld(bytes[idx + 2]) ^ gfmul9(bytes[idx + 3]));
                result[idx + 1] = (byte)(gfmul9(bytes[idx]) ^ gfmule(bytes[idx + 1]) ^ gfmulb(bytes[idx + 2]) ^ gfmuld(bytes[idx + 3]));
                result[idx + 2] = (byte)(gfmuld(bytes[idx]) ^ gfmul9(bytes[idx + 1]) ^ gfmule(bytes[idx + 2]) ^ gfmulb(bytes[idx + 3]));
                result[idx + 3] = (byte)(gfmulb(bytes[idx]) ^ gfmuld(bytes[idx + 1]) ^ gfmul9(bytes[idx + 2]) ^ gfmule(bytes[idx + 3]));
            }
            //hex string
            return "0x" + BitConverter.ToString(result).Replace("-", "");
        }

        public static int gfmul9(int b)
        {
            return (Mul2(Mul2(Mul2(b))) ^ b);
        }
        public static int gfmulb(int b)
        {
            return (Mul2(Mul2(Mul2(b))) ^ Mul2(b) ^ b);
        }
        public static int gfmuld(int b)
        {
            return (Mul2(Mul2(Mul2(b))) ^ Mul2(Mul2(b)) ^ (b));
        }
        public static int gfmule(int b)
        {
            return (Mul2(Mul2(Mul2(b))) ^ Mul2(Mul2(b)) ^ Mul2(b));
        }

    }
}