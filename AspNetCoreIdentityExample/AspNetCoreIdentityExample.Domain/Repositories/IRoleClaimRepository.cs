using AspNetCoreIdentityExample.Domain.Entities;
using System.Collections.Generic;

namespace AspNetCoreIdentityExample.Domain.Repositories
{
    public interface IRoleClaimRepository : IRepository<RoleClaim, int>
    {
        IEnumerable<RoleClaim> FindByRoleId(string roleId);
    }
}
