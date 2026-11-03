using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Davids.Services.AdminIdentity.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddWorkforceRbacAndChangeAudits : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Role",
                table: "AdminUsers",
                type: "nvarchar(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "admin");

            migrationBuilder.CreateTable(
                name: "AdminChangeAuditLogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    OccurredAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    TargetAdminUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TargetEmail = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: false),
                    Action = table.Column<string>(type: "nvarchar(64)", maxLength: 64, nullable: false),
                    ActorAdminUserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ActorEmail = table.Column<string>(type: "nvarchar(320)", maxLength: 320, nullable: true),
                    ActorRole = table.Column<string>(type: "nvarchar(32)", maxLength: 32, nullable: false),
                    ChangedFieldsJson = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CorrelationId = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AdminChangeAuditLogs", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AdminChangeAuditLogs_ActorAdminUserId_OccurredAtUtc",
                table: "AdminChangeAuditLogs",
                columns: new[] { "ActorAdminUserId", "OccurredAtUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_AdminChangeAuditLogs_OccurredAtUtc",
                table: "AdminChangeAuditLogs",
                column: "OccurredAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_AdminChangeAuditLogs_TargetAdminUserId_OccurredAtUtc",
                table: "AdminChangeAuditLogs",
                columns: new[] { "TargetAdminUserId", "OccurredAtUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AdminChangeAuditLogs");

            migrationBuilder.DropColumn(
                name: "Role",
                table: "AdminUsers");
        }
    }
}
