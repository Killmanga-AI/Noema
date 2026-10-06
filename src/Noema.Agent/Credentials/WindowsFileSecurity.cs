using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Noema.Agent.Credentials;

[SupportedOSPlatform("windows")]
internal static class WindowsFileSecurity
{
    /// <summary>
    /// Replaces the file's access list so only administrators and the system have full control and the local service
    /// account, which the agent service runs as, can read it. Ordinary users get no access at all.
    /// </summary>
    public static void RestrictToServiceAccounts(string path)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        foreach (var sid in new[]
        {
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            WindowsIdentity.GetCurrent().User
        })
        {
            if (sid is null)
            {
                continue;
            }

            security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
        }

        security.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalServiceSid, null),
            FileSystemRights.Read,
            AccessControlType.Allow));

        new FileInfo(path).SetAccessControl(security);
    }
}
