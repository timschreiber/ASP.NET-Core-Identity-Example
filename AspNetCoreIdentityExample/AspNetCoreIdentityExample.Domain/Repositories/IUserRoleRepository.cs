using AspNetCoreIdentityExample.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Text;

namespace AspNetCoreIdentityExample.Domain.Repositories
{
    public interface IUserRoleRepository
    {
        void Add(User user, Role role);
        void Remove(User user, Role role);
        IEnumerable<Role> GetRolesByUser(User user);
        IEnumerable<User> GetUsersByRole(Role role);
    }
}
