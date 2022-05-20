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
        double scale = Math.Pow(2.0, 30);
        string url;
        BatchEncoder batchEncoder;
        CKKSEncoder ckksEncoder;
        SEALContext context;
        EncryptionParameters parms;



        public MainPage()
        {
            InitializeComponent();
           

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

        async void HandleHTTP(object sender, System.EventArgs e)
        {

            string schemeType = ((Button)sender).BindingContext as string;

            float a = float.Parse(a_entry.Text);
            float b = float.Parse(b_entry.Text);

            using MemoryStream parmsStream = new MemoryStream();
            using MemoryStream dataAStream = new MemoryStream();
            using MemoryStream dataBStream = new MemoryStream();
            using MemoryStream pkStream = new MemoryStream();
            using MemoryStream rlkStream = new MemoryStream();

            switch (schemeType)
            {
                case "BFV":
                    url = "http://localhost:3000/bfv";
                    parms = new EncryptionParameters(SchemeType.BFV);
                    parms.PolyModulusDegree = 8192;
                    parms.CoeffModulus = CoeffModulus.BFVDefault(8192);
                    parms.PlainModulus = PlainModulus.Batching(8192, 20);
                    context = new SEALContext(parms);
                    break;
                case "BGV":
                    url = "http://localhost:3000/bgv";
                    parms = new EncryptionParameters(SchemeType.BGV);
                    parms.PolyModulusDegree = 8192;
                    parms.CoeffModulus = CoeffModulus.BFVDefault(8192);
                    parms.PlainModulus = PlainModulus.Batching(8192, 20);
                    context = new SEALContext(parms);
                    break;
                case "CKKS":
                    url = "http://localhost:3000/ckks";
                    parms = new EncryptionParameters(SchemeType.CKKS);
                    parms.PolyModulusDegree = 8192;
                    parms.CoeffModulus = CoeffModulus.Create(
                        8192, new int[] { 40, 40, 40, 40, 40 });
                    context = new SEALContext(parms);
                    break;
            }

            KeyGenerator keygen = new KeyGenerator(context);
            SecretKey secretKey = keygen.SecretKey;

            keygen.CreatePublicKey(out PublicKey publicKey);
            keygen.CreateRelinKeys(out RelinKeys relinKeys);

            Encryptor encryptor = new Encryptor(context, publicKey);
            Evaluator evaluator = new Evaluator(context);
            Decryptor decryptor = new Decryptor(context, secretKey);

            parms.Save(parmsStream);
            parmsStream.Seek(0, SeekOrigin.Begin);
            var parmsBase64 = ToBase64(parmsStream);


            publicKey.Save(pkStream);
            pkStream.Seek(0, SeekOrigin.Begin);
            var pkBase64 = ToBase64(pkStream);

            relinKeys.Save(rlkStream);
            rlkStream.Seek(0, SeekOrigin.Begin);
            var rlkBase64 = ToBase64(rlkStream);


            using Plaintext plain1 = new Plaintext();
            using Plaintext plain2 = new Plaintext();

            if (schemeType == "CKKS")
            {

                ckksEncoder = new CKKSEncoder(context);
                ckksEncoder.Encode(a, scale, plain1);
                ckksEncoder.Encode(b, scale, plain2);


            } else {
                batchEncoder = new BatchEncoder(context);
                ulong[] A = new ulong[batchEncoder.SlotCount];
                ulong[] B = new ulong[batchEncoder.SlotCount];
                A[0] = (ulong)a;
                B[0] = (ulong)b;
                batchEncoder.Encode(A, plain1);
                batchEncoder.Encode(B, plain2);
            }

           

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
            var res = await httpClient.PostAsync(this.url, content);
            CKKSres ckksRes = JsonConvert.DeserializeObject<CKKSres>(res.Content.ReadAsStringAsync().Result);
            string encryptedResultBase64 = ckksRes.result;
            MemoryStream encryptedResultStream = ToMemoryStream(encryptedResultBase64);

            using Ciphertext encryptedResult = new Ciphertext();
            encryptedResult.Load(context, encryptedResultStream);

            using Plaintext plainResult = new Plaintext();

            if (schemeType == "CKKS")
            {
                List<double> result = new List<double>();
                decryptor.Decrypt(encryptedResult, plainResult);
                ckksEncoder.Decode(plainResult, result);
                Utilities.PrintVector(result);
                c_Label.Text = "A + B + 100 = " + (result[0]).ToString("0.00000000");
            } else
            {
                List<ulong> result = new List<ulong>();
                decryptor.Decrypt(encryptedResult, plainResult);
                batchEncoder.Decode(plainResult, result);
                Utilities.PrintVector(result);
                c_Label.Text = "A + B + 100 = " + (result[0]).ToString("0.00000000");
            }
            



            
        }
    }
}
