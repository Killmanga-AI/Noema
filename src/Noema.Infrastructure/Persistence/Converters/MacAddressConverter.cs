using System.Net.NetworkInformation;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using Noema.Domain;

namespace Noema.Infrastructure.Persistence.Converters;

/// <summary>Stores a MAC address in the native Postgres macaddr type.</summary>
internal sealed class MacAddressConverter : ValueConverter<MacAddress?, PhysicalAddress?>
{
    public MacAddressConverter()
        : base(
            mac => mac == null ? null : mac.ToPhysicalAddress(),
            physical => physical == null ? null : MacAddress.FromPhysicalAddress(physical))
    {
    }
}
