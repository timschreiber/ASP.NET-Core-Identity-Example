using AspNetCoreIdentityExample.Domain.Entities;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCoreIdentityExample.Domain.Repositories
{
    public interface IUserRepository : IRepository<User>
    {
        User FindByUserName(string userName);
        Task<User> FindByUserNameAsync(string userName);
        Task<User> FindByUserNameAsync(CancellationToken cancellationToken, string userName);

        User FindByEmail(string email);
        Task<User> FindByEmailAsync(string email);
        Task<User> FindByEmailAsync(CancellationToken cancellationToken, string email);
    }
}
