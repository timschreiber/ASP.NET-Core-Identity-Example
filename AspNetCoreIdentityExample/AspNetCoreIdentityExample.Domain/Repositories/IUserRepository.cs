using AspNetCoreIdentityExample.Domain.Entities;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCoreIdentityExample.Domain.Repositories
{
    public interface IUserRepository : IRepository<User, string>
    {
        User FindByNormalizedUserName(string normalizedUserName);

        User FindByNormalizedEmail(string normalizedEmail);
    }
}
