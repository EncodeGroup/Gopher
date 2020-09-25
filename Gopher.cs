using Gopher.Holes;
using System;

namespace Gopher
{
	class Gopher
	{
		private static string Banner()
		{
			string banner = "";

			banner += "\n          o_\n";
			banner += "         /  \"\n";
			banner += "       ,\"  _-\"\n";
			banner += "     ,\"   m m\n";
			banner += "  ..+     )\n";
			banner += "     `m..m\n";

			return banner;
		}

		private static string DigLikeThereIsNoTomorrow()
		{
			bool isHighIntegrity = Utils.IsHighIntegrity();
			string findings = "";

			findings += McAfee.Dig(isHighIntegrity);
			findings += GPP.Dig();
			findings += Unattended.Dig();
			findings += PSReadLine.Dig(isHighIntegrity);
			findings += AWS.Dig(isHighIntegrity);
			findings += Azure.Dig(isHighIntegrity);
			findings += GCP.Dig(isHighIntegrity);
			findings += RDP.Dig(isHighIntegrity);
			findings += PuTTY.Dig(isHighIntegrity);
			findings += SuperPuTTY.Dig(isHighIntegrity);
			findings += WinSCP.Dig(isHighIntegrity);
			findings += FileZilla.Dig(isHighIntegrity);
			findings += VNC.Dig(isHighIntegrity);
			findings += TeamViewer.Dig();

			if (string.IsNullOrEmpty(findings))
			{
				return "\nDid not find anything :(\n";
			}

			else
			{
				return findings;
			}
		}

		public static void Main()
		{
			try
			{
				string banner = Banner();
				string findings = DigLikeThereIsNoTomorrow();
				Console.Write(banner + findings);
				Console.WriteLine("Finished! Returning to my hole.");
			}

			catch (Exception ex)
			{
				Console.WriteLine(ex.Message);
				Console.WriteLine(ex.StackTrace);
			}
		}
	}
}
