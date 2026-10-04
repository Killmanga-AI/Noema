using System;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Noema.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class InitialCreate : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "assets",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: true),
                    hostname = table.Column<string>(type: "character varying(253)", maxLength: 253, nullable: true),
                    hostname_observed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    first_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    retired_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_assets", x => x.id);
                    table.CheckConstraint("ck_assets_seen_order", "last_seen_at >= first_seen_at");
                });

            migrationBuilder.CreateTable(
                name: "scan_runs",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    target = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    probes = table.Column<int>(type: "integer", nullable: false),
                    status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    requested_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    finished_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    failure_reason = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scan_runs", x => x.id);
                    table.CheckConstraint("ck_scan_runs_finished_after_started", "started_at IS NULL OR finished_at IS NULL OR finished_at >= started_at");
                    table.CheckConstraint("ck_scan_runs_status_timestamps", "(status = 'Queued' AND started_at IS NULL AND finished_at IS NULL) OR (status = 'Running' AND started_at IS NOT NULL AND finished_at IS NULL) OR (status IN ('Completed', 'Failed', 'Cancelled') AND finished_at IS NOT NULL)");
                });

            migrationBuilder.CreateTable(
                name: "asset_interfaces",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    asset_id = table.Column<Guid>(type: "uuid", nullable: false),
                    mac_address = table.Column<PhysicalAddress>(type: "macaddr", nullable: true),
                    first_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_asset_interfaces", x => x.id);
                    table.CheckConstraint("ck_asset_interfaces_seen_order", "last_seen_at >= first_seen_at");
                    table.ForeignKey(
                        name: "FK_asset_interfaces_assets_asset_id",
                        column: x => x.asset_id,
                        principalTable: "assets",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "observations",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    scan_run_id = table.Column<Guid>(type: "uuid", nullable: false),
                    kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    address = table.Column<IPAddress>(type: "inet", nullable: false),
                    mac_address = table.Column<PhysicalAddress>(type: "macaddr", nullable: true),
                    observed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    detail_json = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_observations", x => x.id);
                    table.ForeignKey(
                        name: "FK_observations_scan_runs_scan_run_id",
                        column: x => x.scan_run_id,
                        principalTable: "scan_runs",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "interface_addresses",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    asset_interface_id = table.Column<Guid>(type: "uuid", nullable: false),
                    address = table.Column<IPAddress>(type: "inet", nullable: false),
                    first_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_interface_addresses", x => x.id);
                    table.CheckConstraint("ck_interface_addresses_seen_order", "last_seen_at >= first_seen_at");
                    table.ForeignKey(
                        name: "FK_interface_addresses_asset_interfaces_asset_interface_id",
                        column: x => x.asset_interface_id,
                        principalTable: "asset_interfaces",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "ix_asset_interfaces_mac_address",
                table: "asset_interfaces",
                column: "mac_address");

            migrationBuilder.CreateIndex(
                name: "ux_asset_interfaces_asset_id_mac",
                table: "asset_interfaces",
                columns: new[] { "asset_id", "mac_address" },
                unique: true,
                filter: "mac_address IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "ux_asset_interfaces_asset_id_no_mac",
                table: "asset_interfaces",
                column: "asset_id",
                unique: true,
                filter: "mac_address IS NULL");

            migrationBuilder.CreateIndex(
                name: "ix_assets_hostname",
                table: "assets",
                column: "hostname");

            migrationBuilder.CreateIndex(
                name: "ix_assets_last_seen_at",
                table: "assets",
                column: "last_seen_at");

            migrationBuilder.CreateIndex(
                name: "IX_interface_addresses_asset_interface_id",
                table: "interface_addresses",
                column: "asset_interface_id");

            migrationBuilder.CreateIndex(
                name: "ix_interface_addresses_address",
                table: "interface_addresses",
                column: "address");

            migrationBuilder.CreateIndex(
                name: "ux_interface_addresses_interface_id_address",
                table: "interface_addresses",
                columns: new[] { "asset_interface_id", "address" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_observations_address_observed_at",
                table: "observations",
                columns: new[] { "address", "observed_at" });

            migrationBuilder.CreateIndex(
                name: "ix_observations_observed_at",
                table: "observations",
                column: "observed_at");

            migrationBuilder.CreateIndex(
                name: "ix_observations_scan_run_id",
                table: "observations",
                column: "scan_run_id");

            migrationBuilder.CreateIndex(
                name: "ix_scan_runs_requested_at",
                table: "scan_runs",
                column: "requested_at");

            migrationBuilder.CreateIndex(
                name: "ix_scan_runs_status",
                table: "scan_runs",
                column: "status");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "interface_addresses");

            migrationBuilder.DropTable(
                name: "observations");

            migrationBuilder.DropTable(
                name: "asset_interfaces");

            migrationBuilder.DropTable(
                name: "scan_runs");

            migrationBuilder.DropTable(
                name: "assets");
        }
    }
}
