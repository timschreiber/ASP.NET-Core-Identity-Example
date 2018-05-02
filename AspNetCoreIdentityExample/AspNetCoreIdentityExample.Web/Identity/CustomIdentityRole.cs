using System;

namespace AspNetCoreIdentityExample.Web.Identity
{
    public class CustomIdentityRole
    {
        public CustomIdentityRole()
        {
            Id = Guid.NewGuid().ToString();
        }

        public CustomIdentityRole(string roleName)
            : this()
        {
            Name = roleName;
        }

        public string ConcurrencyStamp { get; set; }
        public string Id { get; set; }
        public string Name { get; set; }
        public string NormalizedName { get; set; }

        public override string ToString()
        {
            return Name;
        }
    }
}
