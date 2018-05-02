using AspNetCoreIdentityExample.Domain.Entities;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCoreIdentityExample.Domain.Repositories
{
    public interface IUserLoginRepository : IRepository<UserLogin>
    {
        UserLogin GetByProviderAndKey(string loginProvider, string providerKey);
        Task<UserLogin> GetByProviderAndKeyAsync(string loginProvier, string providerKey);
        Task<UserLogin> GetByProviderAndKeyAsync(CancellationToken cancellationToken, string loginProvider, string providerKey);

        IEnumerable<UserLogin> GetByUserId(string userId);
    }
}
