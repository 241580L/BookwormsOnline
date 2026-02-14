using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BookwormsOnline.Migrations
{
    /// <inheritdoc />
    public partial class MigrateMemberPasswordToIdentityUserId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Add IdentityUserId as nullable first
            migrationBuilder.AddColumn<string>(
                name: "IdentityUserId",
                table: "Members",
                type: "nvarchar(450)",
                nullable: true);

            // Populate IdentityUserId by matching Member.Email to AspNetUsers.Email
            migrationBuilder.Sql(@"
UPDATE m
SET IdentityUserId = u.Id
FROM Members m
INNER JOIN AspNetUsers u ON m.Email = u.Email
");

            // Make IdentityUserId non-nullable (set default empty string for any remaining rows, then enforce non-null)
            migrationBuilder.Sql(@"
UPDATE Members
SET IdentityUserId = ''
WHERE IdentityUserId IS NULL
");
            migrationBuilder.AlterColumn<string>(
                name: "IdentityUserId",
                table: "Members",
                type: "nvarchar(450)",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "nvarchar(450)",
                oldNullable: true);

            // Create index and foreign key to AspNetUsers(Id)
            migrationBuilder.CreateIndex(
                name: "IX_Members_IdentityUserId",
                table: "Members",
                column: "IdentityUserId");

            migrationBuilder.AddForeignKey(
                name: "FK_Members_AspNetUsers_IdentityUserId",
                table: "Members",
                column: "IdentityUserId",
                principalTable: "AspNetUsers",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);

            // Drop the old Password column
            migrationBuilder.DropColumn(
                name: "Password",
                table: "Members");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Re-create Password column (nullable to avoid data loss on down)
            migrationBuilder.AddColumn<string>(
                name: "Password",
                table: "Members",
                type: "nvarchar(max)",
                nullable: true);

            // Attempt to repopulate Password from AspNetUsers.PasswordHash where Email matches
            migrationBuilder.Sql(@"
UPDATE m
SET Password = u.PasswordHash
FROM Members m
INNER JOIN AspNetUsers u ON m.Email = u.Email
");

            // Drop foreign key and index, then drop IdentityUserId column
            migrationBuilder.DropForeignKey(
                name: "FK_Members_AspNetUsers_IdentityUserId",
                table: "Members");

            migrationBuilder.DropIndex(
                name: "IX_Members_IdentityUserId",
                table: "Members");

            migrationBuilder.DropColumn(
                name: "IdentityUserId",
                table: "Members");
        }
    }
}
