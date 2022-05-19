using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using Xamarin.Forms;
using Microsoft.Research.SEAL;
using Newtonsoft.Json;
using System.IO;

namespace SEALMobile


{
    public class CKKSres
    {
        public string result { get; set; }
    }

    public class CKKSreq
    {
        public string parmsBase64 { get; set; }
        public string pkBase64 { get; set; }
        public string dataABase64 { get; set; }
        public string dataBBase64 { get; set; }
        public string rlkBase64 { get; set; }
    }


    public partial class MainPage : ContentPage
    {
        EncryptionParameters parms;
        SEALContext context;
        KeyGenerator keygen;
        PublicKey publicKey;
        RelinKeys relinKeys;
        SecretKey secretKey;
        Encryptor encryptor;
        Evaluator evaluator;
        Decryptor decryptor;
        CKKSEncoder encoder;
        double scale = Math.Pow(2.0, 30);




        public MainPage()
        {
            InitializeComponent();
            parms = new EncryptionParameters(SchemeType.CKKS);

            parms.PolyModulusDegree = 8192;
            parms.CoeffModulus = CoeffModulus.Create(
                8192, new int[] { 40, 40, 40, 40, 40 });


            context = new SEALContext(parms);
            keygen = new KeyGenerator(context);
            secretKey = keygen.SecretKey;

            keygen.CreatePublicKey(out publicKey);
            keygen.CreateRelinKeys(out relinKeys);

            encryptor = new Encryptor(context, publicKey);
            evaluator = new Evaluator(context);
            decryptor = new Decryptor(context, secretKey);

            encoder = new CKKSEncoder(context);

        }

        public static string ToBase64(MemoryStream data)
        {
            var inputAsString = Convert.ToBase64String(data.ToArray());
            return inputAsString;
        }

        public static MemoryStream ToMemoryStream(string data)
        {
            var bytes = Convert.FromBase64String(data);
            var contents = (new MemoryStream(bytes));
            return contents;
        }

        void HandleClick(object sender, System.EventArgs e)
        {
            float a = float.Parse(a_entry.Text);
            float b = float.Parse(b_entry.Text);
            c_Label.Text = "A + B = " + (a + b).ToString("0.00000000");
            Utilities.PrintParameters(context);
        }


        void HandleClickCKKS(object sender, System.EventArgs e)
        {
            float a = float.Parse(a_entry.Text);
            float b = float.Parse(b_entry.Text);


            using Plaintext plain1 = new Plaintext();
            using Plaintext plain2 = new Plaintext();

            encoder.Encode(a, scale, plain1);
            encoder.Encode(b, scale, plain2);

            using Ciphertext encrypted1 = new Ciphertext();
            using Ciphertext encrypted2 = new Ciphertext();
            encryptor.Encrypt(plain1, encrypted1);
            encryptor.Encrypt(plain2, encrypted2);

            using Ciphertext encryptedResult = new Ciphertext();
            using Ciphertext encryptedResult2 = new Ciphertext();
            ulong test = 2;
            evaluator.Add(encrypted1, encrypted2, encryptedResult);
            evaluator.Exponentiate(encryptedResult, test, relinKeys, encryptedResult2);

            using Plaintext plainResult = new Plaintext();
            List<double> result = new List<double>();
            decryptor.Decrypt(encryptedResult2, plainResult);
            encoder.Decode(plainResult, result);
            Console.WriteLine(result[0]);

            c_Label.Text = "A + B = " + (result[1]).ToString("0.00000000");
        }

        async void HandleHTTP(object sender, System.EventArgs e)
        {

            float a = float.Parse(a_entry.Text);
            float b = float.Parse(b_entry.Text);

            using MemoryStream parmsStream = new MemoryStream();
            using MemoryStream dataAStream = new MemoryStream();
            using MemoryStream dataBStream = new MemoryStream();
            using MemoryStream pkStream = new MemoryStream();
            using MemoryStream rlkStream = new MemoryStream();


            //ulong polyModulusDegree = 4096;
            //parms.PolyModulusDegree = polyModulusDegree;
            //parms.CoeffModulus = CoeffModulus.Create(
            //    polyModulusDegree, new int[] { 40, 40 });

            parms.Save(parmsStream);
            parmsStream.Seek(0, SeekOrigin.Begin);
            var parmsBase64 = ToBase64(parmsStream);


            publicKey.Save(pkStream);
            pkStream.Seek(0, SeekOrigin.Begin);
            var pkBase64 = ToBase64(pkStream);

            relinKeys.Save(rlkStream);
            rlkStream.Seek(0, SeekOrigin.Begin);
            var rlkBase64 = ToBase64(rlkStream);

            //relinKeys.Save(dataAStream);
            //relinKeys.Save(dataBStream);

            using Plaintext plain1 = new Plaintext();
            using Plaintext plain2 = new Plaintext();

            encoder.Encode(a, scale, plain1);
            encoder.Encode(b, scale, plain2);

            using Ciphertext encrypted1 = new Ciphertext();
            using Ciphertext encrypted2 = new Ciphertext();
            encryptor.Encrypt(plain1, encrypted1);
            encryptor.Encrypt(plain2, encrypted2);

            encrypted1.Save(dataAStream);
            dataAStream.Seek(0, SeekOrigin.Begin);
            var dataABase64 = ToBase64(dataAStream);

            encrypted2.Save(dataBStream);
            dataBStream.Seek(0, SeekOrigin.Begin);
            var dataBBase64 = ToBase64(dataBStream);

            CKKSreq req = new CKKSreq
            {
                parmsBase64 = parmsBase64, 
                pkBase64 = pkBase64,
                dataABase64 = dataABase64,
                dataBBase64 = dataBBase64,
                rlkBase64 = rlkBase64
            };

            string json = JsonConvert.SerializeObject(req, Formatting.Indented);
            StringContent content = new StringContent(json, Encoding.UTF8, "application/json");

            var httpClient = new HttpClient();
            var res = await httpClient.PostAsync("http://localhost:3000/ckks", content);
            CKKSres ckksRes = JsonConvert.DeserializeObject<CKKSres>(res.Content.ReadAsStringAsync().Result);
            string encryptedResultBase64 = ckksRes.result;
            MemoryStream encryptedResultStream = ToMemoryStream(encryptedResultBase64);

            using Ciphertext encryptedResult = new Ciphertext();
            encryptedResult.Load(context, encryptedResultStream);

            using Plaintext plainResult = new Plaintext();
            List<double> result = new List<double>();
            decryptor.Decrypt(encryptedResult, plainResult);
            encoder.Decode(plainResult, result);
            Utilities.PrintVector(result);



            c_Label.Text = "A + B + 100 = " + (result[0]).ToString("0.00000000");
        }
    }
}
