using AspNetCoreIdentityExample.Domain.Entities;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCoreIdentityExample.Domain.Repositories
{
    public interface IRoleRepository : IRepository<Role, string>
    {
        Role FindByName(string roleName);
    }
}
