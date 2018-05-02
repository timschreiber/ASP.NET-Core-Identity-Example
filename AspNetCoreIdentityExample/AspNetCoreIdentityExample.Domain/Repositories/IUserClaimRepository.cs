using AspNetCoreIdentityExample.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Text;

namespace AspNetCoreIdentityExample.Domain.Repositories
{
    public interface IUserClaimRepository : IRepository<UserClaim>
    {
        IEnumerable<UserClaim> GetByUser(User user);
        IEnumerable<User> GetUsersForClaim(string claimType, string claimValue);
    }
}
