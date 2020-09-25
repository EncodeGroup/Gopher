using Microsoft.Win32;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Gopher.Holes
{
	class RDP
	{
		public static string Dig(bool isHighIntegrity)
		{
			string findings = "";

			if (isHighIntegrity)
			{
				foreach (string sid in Registry.Users.GetSubKeyNames())
				{
					Regex regex = new Regex(@"^S-1-5-21-[\d\-]+$");

					if (regex.IsMatch(sid))
					{
						RegistryKey servers = Registry.Users.OpenSubKey(sid + @"\SOFTWARE\Microsoft\Terminal Server Client\Servers");

						if (servers != null)
						{
							if (servers.SubKeyCount > 0)
							{
								string user = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).ToString();
								findings += string.Format("\n# ---- RDP sessions of user {0} ---- #\n", user.Split('\\')[1]);

								foreach (string server in servers.GetSubKeyNames())
								{
									findings += string.Format("|\n|   Server   : {0}\n", server);
									findings += string.Format("|   Username : {0}\n", servers.OpenSubKey(server).GetValue("UsernameHint").ToString());
								}

								findings += "|\n# ---- #\n";
							}
						}
					}
				}
			}
			else
			{
				RegistryKey servers = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Terminal Server Client\Servers");

				if (servers != null)
				{
					if (servers.SubKeyCount > 0)
					{
						findings += "\n# ---- RDP sessions ---- #\n";

						foreach (string server in servers.GetSubKeyNames())
						{
							findings += string.Format("|\n|   Server   : {0}\n", server);
							findings += string.Format("|   Username : {0}\n", servers.OpenSubKey(server).GetValue("UsernameHint").ToString());
						}

						findings += "|\n# ---- #\n";
					}
				}
			}

			return findings;
		}
	}
}
