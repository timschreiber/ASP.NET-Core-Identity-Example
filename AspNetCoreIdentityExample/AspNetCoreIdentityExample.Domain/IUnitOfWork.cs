using AspNetCoreIdentityExample.Domain.Entities;
using AspNetCoreIdentityExample.Domain.Repositories;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCoreIdentityExample.Domain
{
    public interface IUnitOfWork : IDisposable
    {
        IRoleRepository RoleRepository { get; }
        IRoleClaimRepository RoleClaimRepository { get; }
        IUserRepository UserRepository { get; }
        IUserClaimRepository UserClaimRepository { get; }
        IUserLoginRepository UserLoginRepository { get; }
        IRepository<UserToken> UserTokenRepository { get; }
        IUserRoleRepository UserRoleRepository { get; }

        void Commit();
        Task CommitAsync();
        Task CommitAsync(CancellationToken cancellationToken);
    }
}
