using AspNetCoreIdentityExample.Domain.Entities;
using AspNetCoreIdentityExample.Domain.Repositories;
using System;
using System.Collections.Generic;
using System.Data;

namespace AspNetCoreIdentityExample.Data.Repositories
{
    internal class RoleRepository : RepositoryBase, IRoleRepository
    {
        public RoleRepository(IDbTransaction transaction)
            : base(transaction)
        { }

        public void Add(Role entity)
        {
            Execute(
                sql: "INSERT INTO AspNetRoles(Id, ConcurrencyStamp, [Name], NormalizedName) VALUES(@Id, @ConcurrencyStamp, @Name, @NormalizedName)",
                param: entity
            );
        }

        public IEnumerable<Role> All()
        {
            return Query<Role>(
                sql: "SELECT * FROM AspNetRoles"
            );
        }

        public Role Find(string id)
        {
            return QuerySingle<Role>(
                sql: "SELECT * FROM AspNetRoles WHERE Id = @id",
                param: new { id }
            );
        }

        public Role FindByName(string roleName)
        {
            return QuerySingle<Role>(
                sql: "SELECT * FROM AspNetRoles WHERE [Name] = @roleName",
                param: new { roleName }
            );
        }


        public void Remove(string key)
        {
            Execute(
                sql: "DELETE FROM AspNetRoles WHERE Id = @key",
                param: new { key }
            );

            throw new NotImplementedException();
        }

        public void Update(Role entity)
        {
            Execute(
                sql: "UPDATE AspNetRoles SET ConcurrencyStamp = @ConcurrencyStamp, [Name] = @Name, NormalizedName = @NormalizedName WHERE Id = @Id",
                param: entity
            );
        }
    }
}
