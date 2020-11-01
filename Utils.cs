using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;

namespace Gopher
{
	class Utils
	{
		public static bool IsHighIntegrity()
		{
			WindowsIdentity identity = WindowsIdentity.GetCurrent();
			WindowsPrincipal principal = new WindowsPrincipal(identity);

			return principal.IsInRole(WindowsBuiltInRole.Administrator);
		}

		public static List<string> FindFiles(string path, string pattern)
		{
			List<string> files = new List<string>();

			try
			{
				files.AddRange(Directory.GetFiles(path, pattern, SearchOption.TopDirectoryOnly));

				foreach (string directory in Directory.GetDirectories(path))
				{
					files.AddRange(FindFiles(directory, pattern));
				}
			}
			catch (Exception) { }

			return files;
		}

		public static byte[] HexStringToByteArray(string hex)
		{
			byte[] ba = new byte[hex.ToString().Length / 2];

			for (int i = 0; i < hex.ToString().Length; i += 2)
			{
				ba[i / 2] = Convert.ToByte(hex.ToString().Substring(i, 2), 16);
			}

			return ba;
		}
	}
}
