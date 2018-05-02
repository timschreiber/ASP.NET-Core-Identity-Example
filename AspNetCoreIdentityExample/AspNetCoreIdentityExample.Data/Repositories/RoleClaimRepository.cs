using AspNetCoreIdentityExample.Domain.Entities;
using AspNetCoreIdentityExample.Domain.Repositories;
using System.Collections.Generic;
using System.Data;

namespace AspNetCoreIdentityExample.Data.Repositories
{
    internal class RoleClaimRepository : RepositoryBase, IRoleClaimRepository
    {
        public RoleClaimRepository(IDbTransaction transaction)
            : base(transaction)
        { }

        public void Add(RoleClaim entity)
        {
            entity.Id = ExecuteScalar<int>(
                sql: "INSERT INTO AspNetRoleClaims(ClaimType, ClaimValue, RoldId) VALUES(@ClaimType, @ClaimValue, @RoldId); SELECT SCOPE_IDENTITY()",
                param: entity
            );
        }

        public RoleClaim Find(int key)
        {
            return QuerySingleOrDefault<RoleClaim>(
                sql: "SELECT * FROM AspNetRoleClaims WHERE Id = @key",
                param: new { key }
            );
        }

        public IEnumerable<RoleClaim> FindByRoleId(string roleId)
        {
            return Query<RoleClaim>(
                sql: "SELECT * FROM AspNetRoleClaims WHERE RoleId = @roleId",
                param: new { roleId }
            );
        }

        public IEnumerable<RoleClaim> All()
        {
            return Query<RoleClaim>(
                sql: "SELECT * FROM AspNetRoleClaims"
            );
        }

        public void Remove(int key)
        {
            Execute(
                sql: "DELETE FROM AspNetRoleClaims WHERE Id = @key",
                param: new { key } 
            );
        }

        public void Update(RoleClaim entity)
        {
            Execute(
                sql: "UPDATE AspNetRoleClaims SET ClaimType = @ClaimType, ClaimValue = @ClaimValue, RoleId = @RoleId WHERE Id = @Id",
                param: entity
            );
        }
    }
}
