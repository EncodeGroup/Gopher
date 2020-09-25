using System;
using System.IO;

namespace Gopher.Holes
{
	class AWS
	{
		public static string Dig(bool isHighIntegrity)
		{
			string findings = "";

			if (isHighIntegrity)
			{
				DirectoryInfo di = new DirectoryInfo(@"C:\Users\");

				foreach (DirectoryInfo user in di.GetDirectories())
				{
					string path = user.FullName + @"\.aws\credentials";

					if (File.Exists(path))
					{
						if (new FileInfo(path).Length > 0)
						{
							if (string.IsNullOrEmpty(findings))
							{
								findings += "\n# ---- AWS credential files ---- #\n|\n";
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
			else
			{
				string path = string.Format(@"C:\Users\{0}\.aws\credentials", Environment.GetEnvironmentVariable("USERNAME"));

				if (File.Exists(path))
				{
					if (new FileInfo(path).Length > 0)
					{
						findings += "\n# ---- AWS credential files ---- #\n|\n";
						findings += string.Format("|   {0}\n", path);
						findings += "|\n# ---- #\n";
					}
				}
			}

			return findings;
		}
	}
}
