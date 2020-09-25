using System;
using System.IO;

namespace Gopher.Holes
{
	class Azure
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
						user.FullName + @"\.azure\accessTokens.json",
						user.FullName + @"\.azure\azureProfile.json"
					};

					foreach (string path in paths)
					{
						if (File.Exists(path))
						{
							if (new FileInfo(path).Length > 0)
							{
								if (string.IsNullOrEmpty(findings))
								{
									findings += "\n# ---- Azure credential files ---- #\n|\n";
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
				string username = Environment.GetEnvironmentVariable("USERNAME");
				string[] paths =
				{
					string.Format(@"C:\Users\{0}\.azure\accessTokens.json", username),
					string.Format(@"C:\Users\{0}\.azure\azureProfile.json", username)
				};

				foreach (string path in paths)
				{
					if (File.Exists(path))
					{
						if (new FileInfo(path).Length > 0)
						{
							if (string.IsNullOrEmpty(findings))
							{
								findings += "\n# ---- Azure credential files ---- #\n|\n";
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
