using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MathNet.Numerics.LinearAlgebra;
using MathNet.Numerics.LinearAlgebra.Double;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {
        int plain, plain2, plain3, plain4;
        double cipher, cipher2, cipher3, cipher4;
        public Matrix<double> cofactor_calc(Matrix<double> mtr, int num)
        {
            Matrix<double> matrxRESULT = DenseMatrix.Create(3, 3, 0.0);
            for (int col = 0; col < 3; col++)
            {
                for (int i = 0; i < 5; i++)
                {
                    plain = 0;
                    cipher = 0;

                }
                for (int row = 0; row < 3; row++)
                {
                    int c;
                    if (col == 0)
                        c = 1;
                    else
                        c = 0;
                    int r;
                    if (row == 0)
                        r = 1;
                    else
                        r = 0;
                    int co;
                    if (col == 2)
                        co = 1;
                    else
                        co = 2;
                    int ro;
                    if (row == 2)
                        ro = 1;
                    else
                        ro = 2;
                    double res = ((mtr[c, r] * mtr[co, ro] - mtr[c, ro] * mtr[co, r]) * Math.Pow(-1, col + row) * num) % 26;
                    if (res >= 0)
                        matrxRESULT[col, row] = res;
                    else
                        matrxRESULT[col, row] = res + 26;
                }
            }
            return matrxRESULT;
        }
        public int DETERMENant(Matrix<double> mtrx)
        {
            double result;
            result = mtrx[0, 0] * (mtrx[1, 1] * mtrx[2, 2] - mtrx[1, 2] * mtrx[2, 1]) - mtrx[0, 1] * (mtrx[1, 0] * mtrx[2, 2] - mtrx[1, 2] * mtrx[2, 0]) + mtrx[0, 2] * (mtrx[1, 0] * mtrx[2, 1] - mtrx[1, 1] * mtrx[2, 0]);
            int resultint;
            if ((int)result % 26 >= 0)
            {
                resultint = (int)result % 26;
            }
            else
            {
                resultint = (int)result % 26 + 26;
            }
            for (int counter = 0; counter < 26; counter++)
            {
                if (resultint * counter % 26 == 1)
                {
                    return counter;
                }
            }

            return -1;

        }

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<double> plnmsg;
            plnmsg = plainText.ConvertAll(u => (double)u);

            List<double> cimsg;
            cimsg = cipherText.ConvertAll(u => (double)u);

            int conmtr;
            conmtr = Convert.ToInt32(Math.Sqrt((cimsg.Count)));
            for (int i = 0; i < 5; i++)
            {
                plain = 0;
                cipher = 0;

            }
            Matrix<double> cipher_matrx;

            cipher_matrx = DenseMatrix.OfColumnMajor(conmtr, (int)cipherText.Count / conmtr, cimsg.AsEnumerable());
            Matrix<double> plain_matrix;
            plain_matrix = DenseMatrix.OfColumnMajor(conmtr, (int)plainText.Count / conmtr, plnmsg.AsEnumerable());
            List<int> is_KEY = new List<int>();
            for (int count1 = 0; count1 < 26; count1++)
            {
                for (int count2 = 0; count2 < 26; count2++)
                {
                    for (int count3 = 0; count3 < 26; count3++)
                    {
                        for (int count4 = 0; count4 < 26; count4++)
                        {
                            is_KEY = new List<int>(new[] { count1, count2, count3, count4 });
                            List<int> encA;
                            encA = Encrypt(plainText, is_KEY);
                            if (encA.SequenceEqual(cipherText))
                            {
                                return is_KEY;
                            }

                        }
                    }
                }
            }

            throw new InvalidAnlysisException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<double> ciphermsg;
            ciphermsg = cipherText.ConvertAll(n => (double)n);

            List<double> decrpt_key;
            decrpt_key = key.ConvertAll(n => (double)n);

            int conmtr;
            conmtr = Convert.ToInt32(Math.Sqrt((key.Count)));
            for (int i = 0; i < 5; i++)
            {
                plain = 0;
                cipher = 0;

            }
            Matrix<double> mtrx_of_key;
            mtrx_of_key = DenseMatrix.OfColumnMajor(conmtr, (int)key.Count / conmtr, decrpt_key.AsEnumerable());

            Matrix<double> matx_of_plain;
            matx_of_plain = DenseMatrix.OfColumnMajor(conmtr, (int)cipherText.Count / conmtr, ciphermsg.AsEnumerable());

            List<int> THERESULT = new List<int>();
            if (mtrx_of_key.ColumnCount == 3)
            {
                mtrx_of_key = cofactor_calc(mtrx_of_key.Transpose(), DETERMENant(mtrx_of_key));
            }
            else
            {
                mtrx_of_key = mtrx_of_key.Inverse();
                Console.WriteLine(mtrx_of_key.ToString());
                Console.WriteLine(((int)mtrx_of_key[0, 0]).ToString() + ", " + ((int)mtrx_of_key[0, 0]).ToString());
            }
            if (Math.Abs((int)mtrx_of_key[0, 0]).ToString() != Math.Abs((double)mtrx_of_key[0, 0]).ToString())
            {
                throw new SystemException();
            }
            for (int i = 0; i < matx_of_plain.ColumnCount; i++)
            {
                List<double> Res = new List<double>();
                Res = ((((matx_of_plain.Column(i)).ToRowMatrix() * mtrx_of_key) % 26).Enumerate().ToList());
                for (int j = 0; j < Res.Count; j++)
                {
                    int x = (int)Res[j] >= 0 ? (int)Res[j] : (int)Res[j] + 26;
                    THERESULT.Add(x);
                }
            }

            for (int i = 0; i < THERESULT.Count; i++)
            {
                Console.WriteLine(THERESULT[i].ToString());
            }

            return THERESULT;
        }

        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<double> plainmsg;
            plainmsg = plainText.ConvertAll(u => (double)u);

            int conmtr;
            conmtr = Convert.ToInt32(Math.Sqrt((key.Count)));
            for (int i = 0; i < 5; i++)
            {
                plain = 0;
                cipher = 0;

            }
            List<double> decrpt_key;
            decrpt_key = key.ConvertAll(u => (double)u);


            Matrix<double> mtrx_of_key;
            mtrx_of_key = DenseMatrix.OfColumnMajor(conmtr, (int)key.Count / conmtr, decrpt_key.AsEnumerable());

            Matrix<double> matx_of_plain;
            matx_of_plain = DenseMatrix.OfColumnMajor(conmtr, (int)plainText.Count / conmtr, plainmsg.AsEnumerable());
            List<int> resF;
            resF = new List<int>();
            for (int i = 0; i < matx_of_plain.ColumnCount; i++)
            {
                List<double> THEresult;
                THEresult = new List<double>();
                THEresult = ((((matx_of_plain.Column(i)).ToRowMatrix() * mtrx_of_key) % 26).Enumerate().ToList());
                for (int j = 0; j < THEresult.Count; j++)
                {
                    resF.Add((int)THEresult[j]);
                }
            }

            return resF;
        }

        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            List<double> plainmsg;
            plainmsg = plain3.ConvertAll(u => (double)u);

            List<double> ciphermsg;
            ciphermsg = cipher3.ConvertAll(u => (double)u);
            for (int i = 0; i < 5; i++)
            {
                plain = 0;
                cipher = 0;

            }
            int conmtr;
            conmtr = Convert.ToInt32(Math.Sqrt((ciphermsg.Count)));

            Matrix<double> cipher_matrx;
            cipher_matrx = DenseMatrix.OfColumnMajor(conmtr, (int)cipher3.Count / conmtr, ciphermsg.AsEnumerable());

            Matrix<double> plain_matrx;
            plain_matrx = DenseMatrix.OfColumnMajor(conmtr, (int)plain3.Count / conmtr, plainmsg.AsEnumerable());

            List<int> is_key;
            is_key = new List<int>();

            Matrix<double> mtrx_of_key;
            mtrx_of_key = DenseMatrix.Create(3, 3, 0);

            plain_matrx = cofactor_calc(plain_matrx.Transpose(), DETERMENant(plain_matrx));
            mtrx_of_key = (cipher_matrx * plain_matrx);
            is_key = mtrx_of_key.Transpose().Enumerate().ToList().Select(i => (int)i % 26).ToList();
            is_key.ForEach(i => Console.WriteLine(i.ToString()));
            return is_key;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }
    }
}
