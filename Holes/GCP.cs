using System;
using System.Collections.Generic;
using System.IO;

namespace Gopher.Holes
{
	class GCP
	{
		public static string Dig(bool isHighIntegrity)
		{
			string findings = "";

			if (isHighIntegrity)
			{
				DirectoryInfo di = new DirectoryInfo(@"C:\Users\");

				foreach (DirectoryInfo user in di.GetDirectories())
				{
					List<string> paths = new List<string>
					{
						user.FullName + @"\AppData\Roaming\gcloud\credentials.db",
						user.FullName + @"\AppData\Roaming\gcloud\access_tokens.db"
					};

					paths.AddRange(Utils.FindFiles(user.FullName + @"\AppData\Roaming\gcloud\legacy_credentials", "*"));

					foreach (string path in paths)
					{
						if (File.Exists(path))
						{
							if (new FileInfo(path).Length > 0)
							{
								if (string.IsNullOrEmpty(findings))
								{
									findings += "\n# ---- Google Cloud credential files ---- #\n|\n";
								}

								findings += string.Format("|   {0}\n", path);
							}
						}
					}
				}

				if (!string.IsNullOrEmpty(findings))
				{
					findings += "|\n# ---- #\n";
				}
			}
			else
			{
				string appdata = Environment.GetEnvironmentVariable("APPDATA");

				List<string> paths = new List<string>
				{
					appdata + @"\gcloud\credentials.db",
					appdata + @"\gcloud\access_tokens.db"
				};

				paths.AddRange(Utils.FindFiles(appdata + @"\gcloud\legacy_credentials", "*"));

				foreach (string path in paths)
				{
					if (File.Exists(path))
					{
						if (new FileInfo(path).Length > 0)
						{
							if (string.IsNullOrEmpty(findings))
							{
								findings += "\n# ---- Google Cloud credential files ---- #\n|\n";
							}

							findings += string.Format("|   {0}\n", path);
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
