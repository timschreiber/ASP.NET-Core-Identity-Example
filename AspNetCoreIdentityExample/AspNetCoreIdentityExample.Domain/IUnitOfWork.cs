using AspNetCoreIdentityExample.Domain.Entities;
using AspNetCoreIdentityExample.Domain.Repositories;
using System;

namespace AspNetCoreIdentityExample.Domain
{
    public interface IUnitOfWork : IDisposable
    {
        IRoleRepository RoleRepository { get; }
        IRoleClaimRepository RoleClaimRepository { get; }
        IUserRepository UserRepository { get; }
        IUserClaimRepository UserClaimRepository { get; }
        IUserLoginRepository UserLoginRepository { get; }
        IRepository<UserToken, UserTokenKey> UserTokenRepository { get; }
        IUserRoleRepository UserRoleRepository { get; }

        void Commit();
    }
}
