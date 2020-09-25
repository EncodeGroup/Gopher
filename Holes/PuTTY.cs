using Microsoft.Win32;
using System;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Gopher.Holes
{
	class PuTTY
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
						RegistryKey sessions = Registry.Users.OpenSubKey(sid + @"\SOFTWARE\SimonTatham\PuTTY\Sessions");

						if (sessions != null)
						{
							if (sessions.SubKeyCount > 0)
							{
								string user = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).ToString();
								findings += string.Format("\n# ---- PuTTY sessions of user {0} ---- #\n", user.Split('\\')[1]);

								foreach (string sessionName in sessions.GetSubKeyNames())
								{
									findings += string.Format("|\n|   Session  : {0}\n", Uri.UnescapeDataString(sessionName));
									RegistryKey session = sessions.OpenSubKey(sessionName);
									string hostname = session.GetValue("HostName").ToString();
									object port = session.GetValue("PortNumber");

									if (hostname.Contains("@"))
									{
										findings += string.Format("|   Server   : {0}:{1}\n", hostname.Split('@')[1], Convert.ToInt32(port));
										findings += string.Format("|   Username : {0}\n", hostname.Split('@')[0]);
									}
									else
									{
										findings += string.Format("|   Server   : {0}:{1}\n", hostname, Convert.ToInt32(port));
										string username = session.GetValue("UserName").ToString();

										if (!string.IsNullOrEmpty(username))
										{
											findings += string.Format("|   Username : {0}\n", username);
										}
									}
								}

								findings += "|\n# ---- #\n";
							}
						}
					}
				}
			}
			else
			{
				RegistryKey sessions = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\SimonTatham\PuTTY\Sessions");

				if (sessions != null)
				{
					if (sessions.SubKeyCount > 0)
					{
						findings += "\n# ---- PuTTY sessions ---- #\n";

						foreach (string sessionName in sessions.GetSubKeyNames())
						{
							findings += string.Format("|\n|   Session  : {0}\n", Uri.UnescapeDataString(sessionName));
							RegistryKey session = sessions.OpenSubKey(sessionName);
							string hostname = session.GetValue("HostName").ToString();
							object port = session.GetValue("PortNumber");

							if (hostname.Contains("@"))
							{
								findings += string.Format("|   Server   : {0}:{1}\n", hostname.Split('@')[1], Convert.ToInt32(port));
								findings += string.Format("|   Username : {0}\n", hostname.Split('@')[0]);
							}
							else
							{
								findings += string.Format("|   Server   : {0}:{1}\n", hostname, Convert.ToInt32(port));
								string username = session.GetValue("UserName").ToString();

								if (!string.IsNullOrEmpty(username))
								{
									findings += string.Format("|   Username : {0}\n", username);
								}
							}
						}

						findings += "|\n# ---- #\n";
					}
				}
			}

			return findings;
		}
	}
}
