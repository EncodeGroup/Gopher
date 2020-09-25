using System;
using System.IO;

namespace Gopher.Holes
{
	class PSReadLine
	{
		public static string Dig(bool isHighIntegrity)
		{
			string findings = "";

			if (isHighIntegrity)
			{
				DirectoryInfo di = new DirectoryInfo(@"C:\Users\");

				foreach (DirectoryInfo user in di.GetDirectories())
				{
					string path = user.FullName + @"\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";

					if (File.Exists(path))
					{
						if (new FileInfo(path).Length > 0)
						{
							if (string.IsNullOrEmpty(findings))
							{
								findings += "\n# ---- PowerShell history files ---- #\n|\n";
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
				string path = Environment.GetEnvironmentVariable("APPDATA") + @"\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";

				if (File.Exists(path))
				{
					if (new FileInfo(path).Length > 0)
					{
						findings += "\n# ---- PowerShell history files ---- #\n|\n";
						findings += string.Format("|   {0}\n", path);
						findings += "|\n# ---- #\n";
					}
				}
			}

			return findings;
		}
	}
}
