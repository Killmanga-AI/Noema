using System;
using System.Net;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Noema.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddAgentsAndJobQueue : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "assigned_agent_id",
                table: "scan_runs",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "cancel_requested_at",
                table: "scan_runs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "hosts_responded",
                table: "scan_runs",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<int>(
                name: "last_batch_sequence",
                table: "scan_runs",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "lease_expires_at",
                table: "scan_runs",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "requested_agent_id",
                table: "scan_runs",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "targets_planned",
                table: "scan_runs",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<long>(
                name: "targets_scanned",
                table: "scan_runs",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<uint>(
                name: "xmin",
                table: "scan_runs",
                type: "xid",
                rowVersion: true,
                nullable: false,
                defaultValue: 0u);

            migrationBuilder.CreateTable(
                name: "agents",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    credential_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_seen_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_seen_address = table.Column<IPAddress>(type: "inet", nullable: true),
                    version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    operating_system = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    capabilities = table.Column<int>(type: "integer", nullable: false),
                    reported_ranges = table.Column<string>(type: "text", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_agents", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "enrollment_tokens",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    token_hash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    label = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    created_by_user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    used_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    agent_id = table.Column<Guid>(type: "uuid", nullable: true),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_enrollment_tokens", x => x.id);
                    table.ForeignKey(
                        name: "FK_enrollment_tokens_agents_agent_id",
                        column: x => x.agent_id,
                        principalTable: "agents",
                        principalColumn: "id",
                        onDelete: ReferentialAction.SetNull);
                    table.ForeignKey(
                        name: "FK_enrollment_tokens_users_created_by_user_id",
                        column: x => x.created_by_user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Restrict);
                });

            migrationBuilder.CreateIndex(
                name: "IX_scan_runs_requested_agent_id",
                table: "scan_runs",
                column: "requested_agent_id");

            migrationBuilder.CreateIndex(
                name: "ix_scan_runs_assigned_agent_id",
                table: "scan_runs",
                column: "assigned_agent_id");

            migrationBuilder.CreateIndex(
                name: "ix_scan_runs_status_lease_expires_at",
                table: "scan_runs",
                columns: new[] { "status", "lease_expires_at" });

            migrationBuilder.CreateIndex(
                name: "ix_agents_status",
                table: "agents",
                column: "status");

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_tokens_agent_id",
                table: "enrollment_tokens",
                column: "agent_id");

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_tokens_created_by_user_id",
                table: "enrollment_tokens",
                column: "created_by_user_id");

            migrationBuilder.CreateIndex(
                name: "ix_enrollment_tokens_expires_at",
                table: "enrollment_tokens",
                column: "expires_at");

            migrationBuilder.CreateIndex(
                name: "ux_enrollment_tokens_token_hash",
                table: "enrollment_tokens",
                column: "token_hash",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_scan_runs_agents_assigned_agent_id",
                table: "scan_runs",
                column: "assigned_agent_id",
                principalTable: "agents",
                principalColumn: "id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_scan_runs_agents_requested_agent_id",
                table: "scan_runs",
                column: "requested_agent_id",
                principalTable: "agents",
                principalColumn: "id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_scan_runs_agents_assigned_agent_id",
                table: "scan_runs");

            migrationBuilder.DropForeignKey(
                name: "FK_scan_runs_agents_requested_agent_id",
                table: "scan_runs");

            migrationBuilder.DropTable(
                name: "enrollment_tokens");

            migrationBuilder.DropTable(
                name: "agents");

            migrationBuilder.DropIndex(
                name: "IX_scan_runs_requested_agent_id",
                table: "scan_runs");

            migrationBuilder.DropIndex(
                name: "ix_scan_runs_assigned_agent_id",
                table: "scan_runs");

            migrationBuilder.DropIndex(
                name: "ix_scan_runs_status_lease_expires_at",
                table: "scan_runs");

            migrationBuilder.DropColumn(
                name: "assigned_agent_id",
                table: "scan_runs");

            migrationBuilder.DropColumn(
                name: "cancel_requested_at",
                table: "scan_runs");

            migrationBuilder.DropColumn(
                name: "hosts_responded",
                table: "scan_runs");

            migrationBuilder.DropColumn(
                name: "last_batch_sequence",
                table: "scan_runs");

            migrationBuilder.DropColumn(
                name: "lease_expires_at",
                table: "scan_runs");

            migrationBuilder.DropColumn(
                name: "requested_agent_id",
                table: "scan_runs");

            migrationBuilder.DropColumn(
                name: "targets_planned",
                table: "scan_runs");

            migrationBuilder.DropColumn(
                name: "targets_scanned",
                table: "scan_runs");

            migrationBuilder.DropColumn(
                name: "xmin",
                table: "scan_runs");
        }
    }
}
