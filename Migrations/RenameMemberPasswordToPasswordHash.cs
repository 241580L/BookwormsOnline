using BookwormsOnline.Migrations;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace BookwormsOnline.Migrations
{
    public partial class RenameMemberPasswordToPasswordHash : Migration
    {
        protected void Up2(MigrationBuilder migrationBuilder)
        {
            // Rename column in Members table from Password -> PasswordHash
            migrationBuilder.RenameColumn(
                name: "Password",
                table: "Members",
                newName: "PasswordHash");
        }
    }
}