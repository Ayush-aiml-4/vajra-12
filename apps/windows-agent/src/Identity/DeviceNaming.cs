using System.Net;

namespace Vajra.WindowsAgent.Identity;

/// <summary>
/// Resolves the local Windows machine hostname reliably across environments,
/// falling back safely to "Windows PC" if the name cannot be obtained.
/// Never substitutes server or developer hostnames.
/// </summary>
public static class DeviceNaming
{
    public const string DefaultWindowsName = "Windows PC";

    /// <summary>
    /// Obtains the local Windows machine hostname using supported .NET APIs.
    /// Truncates cleanly to 64 characters to comply with server validation.
    /// </summary>
    public static string GetLocalMachineName()
    {
        try
        {
            var machine = Environment.MachineName?.Trim();
            if (!string.IsNullOrWhiteSpace(machine) && machine.Length >= 2)
            {
                return machine.Length > 64 ? machine.Substring(0, 64).Trim() : machine;
            }
        }
        catch
        {
            // Ignore environment inspection errors
        }

        try
        {
            var host = Dns.GetHostName()?.Trim();
            if (!string.IsNullOrWhiteSpace(host) && host.Length >= 2)
            {
                return host.Length > 64 ? host.Substring(0, 64).Trim() : host;
            }
        }
        catch
        {
            // Ignore DNS lookup errors
        }

        return DefaultWindowsName;
    }
}
