using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Gopher.Holes
{
	class VNC
	{
		private static string Results(Dictionary<string, string> dictionary, string findings)
		{
			if (dictionary.Count > 0)
			{
				int width = 0;

				foreach (string key in dictionary.Keys)
				{
					if (key.Length > width)
					{
						width = key.Length;
					}
				}

				if (string.IsNullOrEmpty(findings))
				{
					findings += "\n# ---- VNC settings ---- #\n|\n";
				}
				else
				{
					findings += "|\n";
				}

				foreach (KeyValuePair<string, string> kvp in dictionary)
				{
					findings += string.Format("|   {0} : {1}\n", kvp.Key.PadRight(width, ' '), kvp.Value);
				}
			}

			return findings;
		}

		//Based heavily on: https://github.com/tpayne86/Powershell/blob/067052520eada3bdf8139a1d8a19cd4328300950/VNC%20Password%20change/encrypt.cs
		private static string Decrypt(byte[] ciphertext)
		{
			if (ciphertext.Length < 8)
			{
				return string.Empty;
			}

			byte[] seed = { 23, 82, 107, 6, 35, 78, 88, 7 };
			byte[] key = new byte[seed.Length];

			for (int i = 0; i < 8; i++)
			{
				key[i] = (byte)(
					((seed[i] & 0x01) << 7) |
					((seed[i] & 0x02) << 5) |
					((seed[i] & 0x04) << 3) |
					((seed[i] & 0x08) << 1) |
					((seed[i] & 0x10) >> 1) |
					((seed[i] & 0x20) >> 3) |
					((seed[i] & 0x40) >> 5) |
					((seed[i] & 0x80) >> 7)
				);
			}

			DES des = new DESCryptoServiceProvider
			{
				Padding = PaddingMode.Zeros,
				Mode = CipherMode.ECB
			};

			return Encoding.UTF8.GetString(des.CreateDecryptor(key, null).TransformFinalBlock(ciphertext, 0, ciphertext.Length));
		}

		private static string Ultra(string findings)
		{
			Dictionary<string, string> dictionary = new Dictionary<string, string>();
			string[] paths =
			{
				@"C:\Program Files\UltraVNC\ultravnc.ini",
				@"C:\Program Files (x86)\UltraVNC\ultravnc.ini",
				@"C:\Program Files\uvnc bvba\UltraVNC\ultravnc.ini",
				@"C:\Program Files (x86)\uvnc bvba\UltraVNC\ultravnc.ini"
			};

			foreach (string path in paths)
			{
				string password = null;
				string viewOnly = null;
				string port = null;

				if (File.Exists(path))
				{
					StreamReader ultraVNC = new StreamReader(path);
					string line;

					while ((line = ultraVNC.ReadLine()) != null)
					{
						if (line.Contains("passwd="))
						{
							string passwd = line.Split('=')[1];
							password = passwd.Substring(0, 16);
						}
						else if (line.Contains("passwd2="))
						{
							string passwd2 = line.Split('=')[1];
							viewOnly = passwd2.Substring(0, 16);
						}
						else if (line.Contains("PortNumber=") && !line.Contains("HTTP") && !line.Contains("=0"))
						{
							port = line.Split('=')[1];
						}
					}

					if (password != null || viewOnly != null)
					{
						dictionary.Add("Server", "UltraVNC");

						if (port != null)
						{
							dictionary.Add("Port", port);
						}

						if (password != null)
						{
							dictionary.Add("Password", Decrypt(Utils.HexStringToByteArray(password)));
						}

						if (viewOnly != null)
						{
							dictionary.Add("View-Only", Decrypt(Utils.HexStringToByteArray(viewOnly)));
						}
					}

					break;
				}
			}

			return Results(dictionary, findings);
		}

		private static string Tiger(bool isHighIntegrity, string findings)
		{
			Dictionary<string, string> dictionary = new Dictionary<string, string>();

			if (isHighIntegrity)
			{
				foreach (string sid in Registry.Users.GetSubKeyNames())
				{
					Regex regex = new Regex(@"^S-1-5-21-[\d\-]+$");

					if (regex.IsMatch(sid))
					{
						RegistryKey tigerVNC = Registry.Users.OpenSubKey(sid + @"\SOFTWARE\TigerVNC\WinVNC4");

						if (tigerVNC != null)
						{
							object password = tigerVNC.GetValue("Password");
							object portNumber = tigerVNC.GetValue("PortNumber");

							if (password != null)
							{
								dictionary.Add("Server", "TigerVNC");

								if (portNumber != null)
								{
									int port = Convert.ToInt32(portNumber);

									if (port != 5900)
									{
										dictionary.Add("Port", port.ToString());
									}
								}

								dictionary.Add("Password", Decrypt((byte[])password));
							}
						}
					}
				}
			}
			else
			{
				RegistryKey tigerVNC = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\TigerVNC\WinVNC4");

				if (tigerVNC != null)
				{
					object password = tigerVNC.GetValue("Password");
					object portNumber = tigerVNC.GetValue("PortNumber");

					if (password != null)
					{
						dictionary.Add("Server", "TigerVNC");

						if (portNumber != null)
						{
							int port = Convert.ToInt32(portNumber);

							if (port != 5900)
							{
								dictionary.Add("Port", port.ToString());
							}
						}

						dictionary.Add("Password", Decrypt((byte[])password));
					}
				}
			}

			return Results(dictionary, findings);
		}

		private static string Tight(bool isHighIntegrity, string findings)
		{
			Dictionary<string, string> dictionary = new Dictionary<string, string>();

			if (isHighIntegrity)
			{
				foreach (string sid in Registry.Users.GetSubKeyNames())
				{
					Regex regex = new Regex(@"^S-1-5-21-[\d\-]+$");

					if (regex.IsMatch(sid))
					{
						RegistryKey tightVNC = Registry.Users.OpenSubKey(sid + @"\SOFTWARE\TightVNC\Server");

						if (tightVNC != null)
						{
							object password = tightVNC.GetValue("Password");
							object viewOnly = tightVNC.GetValue("PasswordViewOnly");
							object control = tightVNC.GetValue("ControlPassword");
							object rfbPort = tightVNC.GetValue("RfbPort");

							if (password != null || viewOnly != null)
							{
								dictionary.Add("Server", "TightVNC");

								if (rfbPort != null)
								{
									int port = Convert.ToInt32(rfbPort);

									if (port != 5900)
									{
										dictionary.Add("Port", port.ToString());
									}
								}

								if (password != null)
								{
									dictionary.Add("Password", Decrypt((byte[])password));
								}

								if (viewOnly != null)
								{
									dictionary.Add("View-Only", Decrypt((byte[])viewOnly));
								}

								if (control != null)
								{
									dictionary.Add("Control", Decrypt((byte[])control));
								}
							}
						}
					}
				}
			}
			else
			{
				RegistryKey tightVNC = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\TightVNC\Server");

				if (tightVNC != null)
				{
					object password = tightVNC.GetValue("Password");
					object viewOnly = tightVNC.GetValue("PasswordViewOnly");
					object control = tightVNC.GetValue("ControlPassword");
					object rfbPort = tightVNC.GetValue("RfbPort");

					if (password != null || viewOnly != null)
					{
						dictionary.Add("Server", "TightVNC");

						if (rfbPort != null)
						{
							int port = Convert.ToInt32(rfbPort);

							if (port != 5900)
							{
								dictionary.Add("Port", port.ToString());
							}
						}

						if (password != null)
						{
							dictionary.Add("Password", Decrypt((byte[])password));
						}

						if (viewOnly != null)
						{
							dictionary.Add("View-Only", Decrypt((byte[])viewOnly));
						}

						if (control != null)
						{
							dictionary.Add("Control", Decrypt((byte[])control));
						}
					}
				}
			}
			
			return Results(dictionary, findings);
		}

		private static string Real(string findings)
		{
			Dictionary<string, string> dictionary = new Dictionary<string, string>();
			RegistryKey realVNC = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\RealVNC\vncserver");

			if (realVNC != null)
			{
				object password = realVNC.GetValue("Password");
				object rfbport = realVNC.GetValue("RfbPort");
				object proxyServer = realVNC.GetValue("ProxyServer");
				object proxyUsername = realVNC.GetValue("ProxyUsername");
				object proxyPassword = realVNC.GetValue("ProxyPassword");

				if (password != null)
				{
					dictionary.Add("Server", "RealVNC");

					if (rfbport != null)
					{
						string portNumber = rfbport.ToString();

						if (portNumber != "5900")
						{
							dictionary.Add("Port", portNumber);
						}
					}

					dictionary.Add("Password", Decrypt(Utils.HexStringToByteArray(password.ToString())));

					if (proxyServer != null)
					{
						dictionary.Add("Proxy Server", proxyServer.ToString());
					}

					if (proxyUsername != null)
					{
						dictionary.Add("Proxy Username", proxyUsername.ToString());
					}

					if (proxyPassword != null)
					{
						dictionary.Add("Proxy Password", Decrypt(Utils.HexStringToByteArray(proxyPassword.ToString())));
					}
				}
			}

			return Results(dictionary, findings);
		}

		public static string Dig(bool isHighIntegrity)
		{
			string findings = "";

			if (isHighIntegrity)
			{
				findings = Real(findings);
			}

			findings = Tight(isHighIntegrity, findings);
			findings = Tiger(isHighIntegrity, findings);
			findings = Ultra(findings);

			if (!string.IsNullOrEmpty(findings))
			{
				findings += "|\n# ---- #\n";
			}

			return findings;
		}
	}
}
