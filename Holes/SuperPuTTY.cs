using System;
using System.IO;
using System.Xml;

namespace Gopher.Holes
{
	class SuperPuTTY
	{
		public static string Dig(bool isHighIntegrity)
		{
			string findings = "";

			if (isHighIntegrity)
			{
				DirectoryInfo di = new DirectoryInfo(@"C:\Users\");

				foreach (DirectoryInfo user in di.GetDirectories())
				{
					string path = user.FullName + @"\Documents\SuperPuTTY\Sessions.XML";

					if (File.Exists(path))
					{
						findings += string.Format("\n# ---- SuperPuTTY sessions of user {0} ---- #\n", user.Name);
						XmlDocument xml = new XmlDocument();
						xml.Load(path);
						XmlNodeList sessionData = xml.GetElementsByTagName("SessionData");

						foreach (XmlNode session in sessionData)
						{
							findings += string.Format("|\n|   Server   : {0}:{1}\n", session.Attributes["Host"].Value, session.Attributes["Port"].Value);
							findings += string.Format("|   Username : {0}\n", session.Attributes["Username"].Value);
						}

						findings += "|\n# ---- #\n";
					}
				}
			}
			else
			{
				string path = @"C:\Users\" + Environment.GetEnvironmentVariable("USERNAME") + @"\Documents\SuperPuTTY\Sessions.XML";

				if (File.Exists(path))
				{
					findings += "\n# ---- SuperPuTTY sessions ---- #\n";
					XmlDocument xml = new XmlDocument();
					xml.Load(path);
					XmlNodeList sessionData = xml.GetElementsByTagName("SessionData");

					foreach (XmlNode session in sessionData)
					{
						findings += string.Format("|\n|   Server   : {0}:{1}\n", session.Attributes["Host"].Value, session.Attributes["Port"].Value);
						findings += string.Format("|   Username : {0}\n", session.Attributes["Username"].Value);
					}

					findings += "|\n# ---- #\n";
				}
			}

			return findings;
		}
	}
}
