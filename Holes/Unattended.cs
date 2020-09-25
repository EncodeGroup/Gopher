using System;
using System.IO;

namespace Gopher.Holes
{
	class Unattended
	{
		public static string Dig()
		{
			string findings = "";
			string windir = Environment.GetEnvironmentVariable("windir");
			string[] paths =
			{
				string.Format(@"{0}\sysprep.inf", windir),
				string.Format(@"{0}\sysprep\sysprep.xml", windir),
				string.Format(@"{0}\sysprep\sysprep.inf", windir),
				string.Format(@"{0}\Panther\Unattended.xml", windir),
				string.Format(@"{0}\Panther\Unattend.xml", windir),
				string.Format(@"{0}\Panther\Unattend\Unattend.xml", windir),
				string.Format(@"{0}\Panther\Unattend\Unattended.xml", windir),
				string.Format(@"{0}\System32\Sysprep\unattend.xml", windir),
				string.Format(@"{0}\System32\Sysprep\Panther\unattend.xml", windir)
			};

			foreach (string path in paths)
			{
				if (File.Exists(path))
				{
					if (string.IsNullOrEmpty(findings))
					{
						findings += "\n# ---- Unattended installation files ---- #\n|\n";
					}

					findings += string.Format("|   {0}\n", path);
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
