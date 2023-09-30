using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Globalization;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {
        string[] toBinary = Enumerable.Range(0, 16).Select(i => Convert.ToString(i, 2).PadLeft(4, '0')).ToArray();

        int[] LeftShifts = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
        int[] PC1 =
        {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        };
        int[] PC2 =
      {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
        };
        int[] IP =
        {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
        };
        int[] ExpansionMat =
        {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        };
        int[] P =
        {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
        };
        int[] IPinverse =
        {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
        };
        int[,] SBoxes =
        {
            {
                14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
            },
            {
                15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
            },
            {
                10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
            },
            {
                7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
            },
            {
                2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
            },
            {
                12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
            },
            {
                4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
            },
            {
                13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
            }
        };

        char Xor(char x, char y)
        {
            if ((x == '0' && y == '1') || (x == '1' && y == '0'))
                return '1';

            return '0';
        }

        int toInt2(string input)
        {
            switch (input)
            {
                case "00":
                    return 0;
                case "01":
                    return 1;
                case "10":
                    return 2;
                default:
                    return 3;
            }
        }

        int toInt4(string input)
        {
            switch (input)
            {
                case "0000":
                    return 0;
                case "0001":
                    return 1;
                case "0010":
                    return 2;
                case "0011":
                    return 3;
                case "0100":
                    return 4;
                case "0101":
                    return 5;
                case "0110":
                    return 6;
                case "0111":
                    return 7;
                case "1000":
                    return 8;
                case "1001":
                    return 9;
                case "1010":
                    return 10;
                case "1011":
                    return 11;
                case "1100":
                    return 12;
                case "1101":
                    return 13;
                case "1110":
                    return 14;
                default:
                    return 15;
            }
        }

        char toHEX(string input)
        {
            switch (input)
            {
                case "0000":
                    return '0';
                case "0001":
                    return '1';
                case "0010":
                    return '2';
                case "0011":
                    return '3';
                case "0100":
                    return '4';
                case "0101":
                    return '5';
                case "0110":
                    return '6';
                case "0111":
                    return '7';
                case "1000":
                    return '8';
                case "1001":
                    return '9';
                case "1010":
                    return 'A';
                case "1011":
                    return 'B';
                case "1100":
                    return 'C';
                case "1101":
                    return 'D';
                case "1110":
                    return 'E';
                default:
                    return 'F';
            }
        }


        public override string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            string plainText = String.Empty;


            //convert key to string of 1's and 0's
            StringBuilder binaryKey = new StringBuilder();


            for (int i = 2; i < key.Length; i++)
            {
                binaryKey.Append(toBinary[int.Parse(key[i].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);

            }

            // apply PC_1
            StringBuilder pc1 = new StringBuilder();

            for (int i = 0; i < this.PC1.Length; i++)
            {
                pc1.Append(binaryKey[this.PC1[i] - 1]);
            }
            //How to calculate   CN and DN 

            string[] c_n = new string[17];
            string[] d_n = new string[17];

            c_n[0] = pc1.ToString().Substring(0, 28);
            d_n[0] = pc1.ToString().Substring(28, 28);

            string c_shifted = c_n[0];
            string d_shifted = d_n[0];
            char rightMost;

            for (int i = 0; i < 16; i++)

            {
                for (int j = 0; j < LeftShifts[i]; j++)
                {
                    rightMost = c_shifted[0];
                    c_shifted = c_shifted.Remove(0, 1);
                    c_shifted += rightMost;

                    rightMost = d_shifted[0];
                    d_shifted = d_shifted.Remove(0, 1);
                    d_shifted += rightMost;

                }
                c_n[i + 1] = c_shifted;
                d_n[i + 1] = d_shifted;

            }

            //calculate Kn
            string[] K_n = new string[16];
            int temp = 0;
            while (temp < K_n.Length)
            {
                K_n[temp] = c_n[temp + 1] + d_n[temp + 1];
                temp++;
            }

            //How to find pc2 &apply pc2

            StringBuilder[] roundKey = new StringBuilder[16];
            int q1 = 0;
            while (q1 < K_n.Length)
            {
                roundKey[q1] = new StringBuilder();
                for (int i = 0; i < PC2.Length; i++)

                {
                    roundKey[q1].Append(K_n[q1][PC2[i] - 1]);

                }
                q1++;
            }

            // decrypting 

            //convert palint text to the opposite (0's & 1's)
            StringBuilder binaryCipherText = new StringBuilder();
            int J = 2;

            do
            {
                binaryCipherText.Append(toBinary[int.Parse(cipherText[J].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
                J++;
            } while (J < key.Length);

            //apply the permutation



            StringBuilder initialPermutation = new StringBuilder();


            foreach (int idx in IP)
            {
                initialPermutation.Append(binaryCipherText[idx - 1]);
            }


            //calculate Ln and Rn
            string[] L_n = new string[17];
            string[] R_n = new string[17];

            L_n[0] = initialPermutation.ToString().Substring(0, 32);
            R_n[0] = initialPermutation.ToString().Substring(32, 32);

            StringBuilder expandedR;
            StringBuilder xor;
            StringBuilder sbox;
            StringBuilder perms;
            string Bn;
            int row;
            int column;

            //repeat process for 16 round
            for (int round = 1; round < 17; round++)
            {
                L_n[round] = R_n[round - 1];
                expandedR = new StringBuilder();

                xor = new StringBuilder();

                perms = new StringBuilder();

                sbox = new StringBuilder();


                //expand R
                for (int f = 0; f < ExpansionMat.Length; f++)
                {
                    expandedR.Append(R_n[round - 1][ExpansionMat[f] - 1]);
                }
                // Ri xor with Ki
                int R1 = 0;
                while (R1 < expandedR.Length)
                {
                    //check
                    xor.Append(Xor(expandedR[R1], roundKey[15 - (round - 1)][R1]));
                    R1++;
                }
                // applying sbox
                for (int S1 = 0; S1 < 8; S1++)
                {
                    Bn = xor.ToString().Substring(6 * S1, 6);
                    row = toInt2(Bn[0] + string.Empty + Bn[5]);
                    column = toInt4(Bn.Substring(1, 4));
                    sbox.Append(toBinary[SBoxes[S1, (row * 16) + column]]);
                }
                //applying permutation
                int p1 = 0;
                while (p1 < P.Length)
                {
                    perms.Append(sbox[P[p1] - 1]);
                    p1++;
                }
                //How calculate Ri
                xor = new StringBuilder();
                int RI = 0;
                while (RI < perms.Length)
                {
                    //chceck
                    xor.Append(Xor(L_n[round - 1][RI], perms[RI]));
                    RI++;
                }
                R_n[round] = xor.ToString();
            }

            string RL_16 = R_n[16] + L_n[16];
            StringBuilder binaryPlainText = new StringBuilder();
            //apply p^-1
            for (int i = 0; i < IPinverse.Length; i++)
            {
                binaryPlainText.Append(RL_16[IPinverse[i] - 1]);

            }

            //conver output to HEX
            plainText += "0x";

            for (int i = 0; i < 16; i++)
            {
                plainText += toHEX(binaryPlainText.ToString().Substring(4 * i, 4));

            }
            return plainText;
        }

        public override string Encrypt(string plainText, string key)
        {
            // throw new NotImplementedException();
            string cipherText = String.Empty;
            int r = 0;

            StringBuilder expandedR;
            StringBuilder XopOut;
            StringBuilder sboxOut;
            StringBuilder permsOut;
            string Bn;
            int row;
            int column;

            int y = 0;

            //convert key to string of 1's and 0's
            StringBuilder binaryKey = new StringBuilder();

            int e = 0;
            for (int i = 2; i < key.Length; i++)
            {
                binaryKey.Append(toBinary[int.Parse(key[i].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
            }
            for (int i = 2; i < key.Length; i++)
            {

            }


            // apply PC1
            StringBuilder PC1key = new StringBuilder();

            for (int i = 0; i < PC1.Length; i++)
            {
                PC1key.Append(binaryKey[PC1[i] - 1]);
            }

            //calculate Cn and Dn 
            string[] C = new string[17];
            string[] D = new string[17];

            C[0] = PC1key.ToString().Substring(0, 28);
            D[0] = PC1key.ToString().Substring(28, 28);

            string c_shifted = C[0];
            string d_shifted = D[0];
            char rightMost;

            while (e < 16)
            {
                int w = 0;

                while (w < LeftShifts[e])
                {
                    rightMost = c_shifted[0];
                    c_shifted = c_shifted.Remove(0, 1);
                    c_shifted += rightMost;

                    rightMost = d_shifted[0];
                    d_shifted = d_shifted.Remove(0, 1);
                    d_shifted += rightMost;
                    w++;
                }
                C[e + 1] = c_shifted;
                D[e + 1] = d_shifted;
                e++;
            }

            //calculate Kn
            string[] K = new string[16];

            /*while (r < K.Length)
            {
                K[r] = C[r + 1] + D[r + 1];
                r++;
            }*/
            for (r = 0; r < K.Length; r++)
            {
                K[r] = C[r + 1] + D[r + 1];
            }

            for (r = 0; r < K.Length; r++)
            {

            }

            //apply PC2
            StringBuilder[] roundKey = new StringBuilder[16];

            int h = 0;
            while (h < K.Length)
            {
                roundKey[h] = new StringBuilder();
                int j = 0;
                while (j < PC2.Length)
                {
                    roundKey[h].Append(K[h][PC2[j] - 1]);
                    j++;
                }
                h++;
            }

            //start encrypting plain text
            //convert plain text to array of 0's and 1's
            StringBuilder binaryPlainText = new StringBuilder();
            int t = 2;
            while (t < key.Length)
            {
                binaryPlainText.Append(toBinary[int.Parse(plainText[t].ToString(), NumberStyles.HexNumber, CultureInfo.InvariantCulture)]);
                t++;
            }//here5

            //apply initial perm
            StringBuilder initialPerm = new StringBuilder();

            foreach (int index in IP)
            {
                initialPerm.Append(binaryPlainText[index - 1]);
            }


            //calculate Ln and Rn
            string[] L = new string[17];
            string[] R = new string[17];

            L[0] = initialPerm.ToString().Substring(0, 32);
            R[0] = initialPerm.ToString().Substring(32, 32);


            int a = 1;

            for (a = 1; a < 17; a++)
            {
                L[a] = R[a - 1];
                expandedR = new StringBuilder();
                XopOut = new StringBuilder();
                sboxOut = new StringBuilder();
                permsOut = new StringBuilder();

                //expand R
                int j = 0;
                while (j < ExpansionMat.Length)
                {
                    expandedR.Append(R[a - 1][ExpansionMat[j] - 1]);
                    j++;
                }

                // E(Ri) apli_xop Ki
                j = 0;
                while (j < expandedR.Length)
                {
                    XopOut.Append(Xor(expandedR[j], roundKey[a - 1][j]));
                    j++;
                }

                // apply sbox
                int k = 0;
                while (k < 8)
                {
                    Bn = XopOut.ToString().Substring(6 * k, 6);
                    row = toInt2(Bn[0] + string.Empty + Bn[5]);
                    column = toInt4(Bn.Substring(1, 4));
                    sboxOut.Append(toBinary[SBoxes[k, (row * 16) + column]]);
                    k++;
                }

                //apply permutation
                j = 0;
                while (j < P.Length)
                {
                    permsOut.Append(sboxOut[P[j] - 1]);
                    j++;
                }

                //calculate Ri
                XopOut = new StringBuilder();
                j = 0;
                while (j < permsOut.Length)
                {
                    XopOut.Append(Xor(L[a - 1][j], permsOut[j]));
                    j++;
                }

                R[a] = XopOut.ToString();
            }


            string R16_L16 = R[16] + L[16];
            StringBuilder binaryCipher = new StringBuilder();

            foreach (int i in IPinverse)
            {
                binaryCipher.Append(R16_L16[i - 1]);
            }

            //conver output to HEX
            cipherText += "0x";

            int output = 0;
            do
            {
                cipherText += toHEX(binaryCipher.ToString().Substring(4 * output, 4));
                output++;
            } while (output < 16);

            return cipherText;
        }
    }
}