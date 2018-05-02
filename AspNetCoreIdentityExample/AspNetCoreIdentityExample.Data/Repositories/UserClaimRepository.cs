using AspNetCoreIdentityExample.Domain.Entities;
using AspNetCoreIdentityExample.Domain.Repositories;
using System;
using System.Collections.Generic;
using System.Data;
using System.Text;

namespace AspNetCoreIdentityExample.Data.Repositories
{
    internal class UserClaimRepository : RepositoryBase, IUserClaimRepository
    {
        public UserClaimRepository(IDbTransaction transaction)
            : base(transaction)
        {
        }

        public void Add(UserClaim entity)
        {
            entity.Id = ExecuteScalar<int>(
                sql: "INSERT INTO AspNetUserClaims(ClaimType, ClaimValue, UserId) VALUES(@ClaimType, @ClaimValue, @UserId); SELECT SCOPE_IDENTITY()",
                param: entity
            );
        }

        public IEnumerable<UserClaim> All()
        {
            return Query<UserClaim>(
                sql: "SELECT Id, ClaimType, ClaimValue, UserId FROM AspNetUserClaims"
            );
        }

        public UserClaim Find(int id)
        {
            return QuerySingle<UserClaim>(
                sql: "SELECT Id, ClaimType, ClaimValue, UserId FROM AspNetUserClaims WHERE Id = @id",
                param: new { id }
            );
        }

        public IEnumerable<UserClaim> GetByUserId(string userId)
        {
            return Query<UserClaim>(
                sql: "SELECT Id, ClaimType, ClaimValue, UserId FROM AspNetUserClaims WHERE UserId = @userId",
                param: new { userId }
            );
        }

        public IEnumerable<User> GetUsersForClaim(string claimType, string claimValue)
        {
            return Query<User>(
                sql: @"
                    SELECT
	                    u.Id, u.AccessFailedCount, u.ConcurrencyStamp, u.Email, u.EmailConfirmed,
	                    u.LockoutEnabled, u.LockoutEnd, u.NormalizedEmail, u.NormalizedUserName,
	                    u.PasswordHash, u.PhoneNumber, u.PhoneNumberConfirmed, u.SecurityStamp,
	                    u.TwoFactorEnabled, u.UserName
                    FROM
	                    AspNetUserClaims c INNER JOIN AspNetUsers u ON c.UserId = u.Id
                    WHERE
	                    c.ClaimType = @claimType AND c.ClaimValue = @claimValue
                ",
                param: new { claimType, claimValue }
            );
        }

        public void Remove(int key)
        {
            Execute(
                sql: "DELETE FROM AspNetUserClaims WHERE Id = @key",
                param: new { key }
            );
        }

        public void Update(UserClaim entity)
        {
            Execute(
                sql: "UPDATE AspNetUserClaims SET ClaimType = @ClaimType, ClaimValue = @ClaimValue, UserId = @UserId WHERE Id = @Id",
                param: entity
            );
        }
    }
}
