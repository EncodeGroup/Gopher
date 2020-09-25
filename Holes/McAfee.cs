using System;
using System.Collections.Generic;

namespace Gopher.Holes
{
	class McAfee
	{
		public static string Dig(bool isHighIntegrity)
		{
			string findings = "";
			List<string> files = new List<string>();
			List<string> paths = new List<string>
			{
				@"C:\ProgramData\",
				@"C:\Program Files\",
				@"C:\Program Files (x86)\"
			};

			if (isHighIntegrity)
			{
				paths.Add(@"C:\Users\");
			}
			else
			{
				paths.Add(string.Format(@"C:\Users\{0}\", Environment.GetEnvironmentVariable("USERNAME")));
			}

			foreach (string path in paths)
			{
				files.AddRange(Utils.FindFiles(path, "SiteList.xml"));
				files.AddRange(Utils.FindFiles(path, "SiteMgr.xml"));
			}

			foreach (string file in files)
			{
				if (string.IsNullOrEmpty(findings))
				{
					findings += "\n# ---- McAfee repository list files ---- #\n|\n";
				}

				findings += string.Format("|   {0}\n", file);
			}

			if (!string.IsNullOrEmpty(findings))
			{
				findings += "|\n# ---- #\n";
			}

			return findings;
		}
	}
}
