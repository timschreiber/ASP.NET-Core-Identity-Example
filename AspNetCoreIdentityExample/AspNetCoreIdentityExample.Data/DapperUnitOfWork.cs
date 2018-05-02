using AspNetCoreIdentityExample.Domain;
using AspNetCoreIdentityExample.Domain.Entities;
using AspNetCoreIdentityExample.Domain.Repositories;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCoreIdentityExample.Data
{
    public class DapperUnitOfWork : IUnitOfWork
    {
        public DapperUnitOfWork(string connectionString)
        { }

        public IRoleRepository RoleRepository => throw new NotImplementedException();

        public IRoleClaimRepository RoleClaimRepository => throw new NotImplementedException();

        public IUserRepository UserRepository => throw new NotImplementedException();

        public IUserClaimRepository UserClaimRepository => throw new NotImplementedException();

        public IUserLoginRepository UserLoginRepository => throw new NotImplementedException();

        public IRepository<UserToken> UserTokenRepository => throw new NotImplementedException();

        public IUserRoleRepository UserRoleRepository => throw new NotImplementedException();

        public void Commit()
        {
            throw new NotImplementedException();
        }

        public Task CommitAsync()
        {
            throw new NotImplementedException();
        }

        public Task CommitAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }
    }
}
