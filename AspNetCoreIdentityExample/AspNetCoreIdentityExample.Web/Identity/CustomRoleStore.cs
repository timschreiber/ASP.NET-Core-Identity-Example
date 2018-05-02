using AspNetCoreIdentityExample.Domain;
using AspNetCoreIdentityExample.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCoreIdentityExample.Web.Identity
{
    public class CustomRoleStore :
        IRoleStore<CustomIdentityRole>,
        IRoleClaimStore<CustomIdentityRole>
    {
        private readonly IUnitOfWork _unitOfWork;

        public CustomRoleStore(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        #region IRoleStore<CustomIdentityRole> Members
        public Task<IdentityResult> CreateAsync(CustomIdentityRole role, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (role == null)
                    throw new ArgumentNullException(nameof(role));

                var roleEntity = getRoleEntity(role);

                _unitOfWork.RoleRepository.Add(roleEntity);
                _unitOfWork.Commit();

                return Task.FromResult(IdentityResult.Success);
            }
            catch(Exception ex)
            {
                return Task.FromResult(IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message }));
            }
        }

        public Task<IdentityResult> DeleteAsync(CustomIdentityRole role, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (role == null)
                    throw new ArgumentNullException(nameof(role));

                _unitOfWork.RoleRepository.Remove(role.Id);
                _unitOfWork.Commit();

                return Task.FromResult(IdentityResult.Success);
            }
            catch (Exception ex)
            {
                return Task.FromResult(IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message }));
            }
        }

        public Task<CustomIdentityRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(roleId))
                throw new ArgumentNullException(nameof(roleId));

            if(!Guid.TryParse(roleId, out Guid id))
                throw new ArgumentOutOfRangeException(nameof(roleId), $"{nameof(roleId)} is not a valid GUID");

            var roleEntity = _unitOfWork.RoleRepository.Find(id.ToString());
            return Task.FromResult(getIdentityRole(roleEntity));
        }

        public Task<CustomIdentityRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(normalizedRoleName))
                throw new ArgumentNullException(nameof(normalizedRoleName));

            var roleEntity = _unitOfWork.RoleRepository.FindByName(normalizedRoleName);
            return Task.FromResult(getIdentityRole(roleEntity));
        }

        public Task<string> GetNormalizedRoleNameAsync(CustomIdentityRole role, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.NormalizedName);
        }

        public Task<string> GetRoleIdAsync(CustomIdentityRole role, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.Id);
        }

        public Task<string> GetRoleNameAsync(CustomIdentityRole role, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.Name);
        }

        public Task SetNormalizedRoleNameAsync(CustomIdentityRole role, string normalizedName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            role.NormalizedName = normalizedName;

            return Task.CompletedTask;
        }

        public Task SetRoleNameAsync(CustomIdentityRole role, string roleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            role.Name = roleName;

            return Task.CompletedTask;
        }

        public Task<IdentityResult> UpdateAsync(CustomIdentityRole role, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (role == null)
                    throw new ArgumentNullException(nameof(role));

                var roleEntity = getRoleEntity(role);

                _unitOfWork.RoleRepository.Update(roleEntity);
                _unitOfWork.Commit();

                return Task.FromResult(IdentityResult.Success);
            }
            catch (Exception ex)
            {
                return Task.FromResult(IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message }));
            }
        }

        public void Dispose()
        {
            // Lifetimes of dependencies are managed by the IoC container, so disposal here is unnecessary.
        }
        #endregion

        #region IRoleClaimStore<CustomIdentityRole> Members
        public Task<IList<Claim>> GetClaimsAsync(CustomIdentityRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            IList<Claim> result = _unitOfWork.RoleClaimRepository.FindByRoleId(role.Id).Select(x => new Claim(x.ClaimType, x.ClaimValue)).ToList();

            return Task.FromResult(result);
        }

        public Task AddClaimAsync(CustomIdentityRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            var roleClaimEntity = new RoleClaim
            {
                ClaimType = claim.Type,
                ClaimValue = claim.Value,
                RoleId = role.Id
            };

            _unitOfWork.RoleClaimRepository.Add(roleClaimEntity);
            _unitOfWork.Commit();

            return Task.CompletedTask;
        }

        public Task RemoveClaimAsync(CustomIdentityRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (role == null)
                throw new ArgumentNullException(nameof(role));

            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            var roleClaimEntity = _unitOfWork.RoleClaimRepository.FindByRoleId(role.Id)
                .SingleOrDefault(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);

            if(roleClaimEntity != null)
            {
                _unitOfWork.RoleClaimRepository.Remove(roleClaimEntity.Id);
                _unitOfWork.Commit();
            }

            return Task.CompletedTask;
        }
        #endregion

        #region Private Methods
        private Role getRoleEntity(CustomIdentityRole value)
        {
            return value == null
                ? default(Role)
                : new Role
                {
                    ConcurrencyStamp = value.ConcurrencyStamp,
                    Id = value.Id,
                    Name = value.Name,
                    NormalizedName = value.NormalizedName
                };
        }

        private CustomIdentityRole getIdentityRole(Role value)
        {
            return value == null
                ? default(CustomIdentityRole)
                : new CustomIdentityRole
                {
                    ConcurrencyStamp = value.ConcurrencyStamp,
                    Id = value.Id,
                    Name = value.Name,
                    NormalizedName = value.NormalizedName
                };
        }
        #endregion
    }
}
