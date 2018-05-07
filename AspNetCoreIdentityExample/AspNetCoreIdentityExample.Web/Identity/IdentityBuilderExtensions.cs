using AspNetCoreIdentityExample.Web.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCoreIdentityExample.Web.Identity
{
    public static class IdentityBuilderExtensions
    {
        public static IdentityBuilder AddCustomStores(this IdentityBuilder builder)
        {
            builder.Services.AddTransient<IUserStore<ApplicationUser>, CustomUserStore>();
            builder.Services.AddTransient<IRoleStore<IdentityRole>, CustomRoleStore>();
            return builder;
        }
    }
}
