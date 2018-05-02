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
    public class CustomUserStore :
        IUserStore<CustomIdentityUser>,
        IUserPasswordStore<CustomIdentityUser>,
        IUserEmailStore<CustomIdentityUser>,
        IUserLoginStore<CustomIdentityUser>,
        IUserRoleStore<CustomIdentityUser>,
        IUserSecurityStampStore<CustomIdentityUser>,
        IUserClaimStore<CustomIdentityUser>,
        IUserAuthenticationTokenStore<CustomIdentityUser>,
        IUserTwoFactorStore<CustomIdentityUser>,
        IUserPhoneNumberStore<CustomIdentityUser>,
        IUserLockoutStore<CustomIdentityUser>,
        IQueryableUserStore<CustomIdentityUser>
    {
        private readonly IUnitOfWork _unitOfWork;

        public CustomUserStore(IUnitOfWork unitOfWork)
        {
            _unitOfWork = unitOfWork;
        }

        #region IQueryableUserStore<CustomIdentityUser> Members
        public IQueryable<CustomIdentityUser> Users
        {
            get
            {
                return _unitOfWork.UserRepository.GetAll()
                    .Select(x => getIdentityUser(x))
                    .AsQueryable();
            }
        }
        #endregion

        #region IUserStore<CustomIdentityUser> Members
        public Task<IdentityResult> CreateAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (user == null)
                    throw new ArgumentNullException(nameof(user));

                var entity = getUserEntity(user);

                _unitOfWork.UserRepository.Add(entity);
                _unitOfWork.Commit();

                return Task.FromResult(IdentityResult.Success);
            }
            catch (Exception ex)
            {
                return Task.FromResult(IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message }));
            }
        }

        public Task<IdentityResult> DeleteAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (user == null)
                    throw new ArgumentNullException(nameof(user));

                var entity = getUserEntity(user);

                _unitOfWork.UserRepository.Remove(entity);
                _unitOfWork.Commit();

                return Task.FromResult(IdentityResult.Success);
            }
            catch (Exception ex)
            {
                return Task.FromResult(IdentityResult.Failed(new IdentityError { Code = ex.Message, Description = ex.Message }));
            }
        }

        public Task<CustomIdentityUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if(Guid.TryParse(userId, out Guid id))
            {
                var userEntity = _unitOfWork.UserRepository.Find(id);
                return Task.FromResult(getIdentityUser(userEntity));
            }
            else
            {
                throw new ArgumentOutOfRangeException(nameof(userId), $"{nameof(userId)} is not a valid GUID");
            }
        }

        public Task<CustomIdentityUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(normalizedUserName))
                throw new ArgumentNullException(nameof(normalizedUserName));

            var userEntity = _unitOfWork.UserRepository.FindByUserName(normalizedUserName);
            return Task.FromResult(getIdentityUser(userEntity));
        }

        public Task<string> GetNormalizedUserNameAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.NormalizedUserName);
        }

        public Task<string> GetUserIdAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.UserName);
        }

        public Task SetNormalizedUserNameAsync(CustomIdentityUser user, string normalizedName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(normalizedName))
                throw new ArgumentNullException(nameof(normalizedName));

            user.NormalizedUserName = normalizedName;

            return Task.CompletedTask;
        }

        public Task SetUserNameAsync(CustomIdentityUser user, string userName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(userName))
                throw new ArgumentNullException(nameof(userName));

            user.UserName = userName;

            return Task.CompletedTask;
        }

        public Task<IdentityResult> UpdateAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            try
            {
                if (cancellationToken != null)
                    cancellationToken.ThrowIfCancellationRequested();

                if (user == null)
                    throw new ArgumentNullException(nameof(user));

                var userEntity = getUserEntity(user);

                _unitOfWork.UserRepository.Update(userEntity);
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

        #region IUserPasswordStore<CustomIdentityUser> Members
        public Task SetPasswordHashAsync(CustomIdentityUser user, string passwordHash, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(passwordHash))
                throw new ArgumentNullException(nameof(passwordHash));

            user.PasswordHash = passwordHash;

            return Task.CompletedTask;
        }

        public Task<string> GetPasswordHashAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(!string.IsNullOrWhiteSpace(user.PasswordHash));
        }
        #endregion

        #region IUserEmailStore<CustomIdentityUser> Members
        public Task SetEmailAsync(CustomIdentityUser user, string email, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(email))
                throw new ArgumentNullException(nameof(email));

            user.Email = email;

            return Task.CompletedTask;
        }

        public Task<string> GetEmailAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailConfirmedAsync(CustomIdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.EmailConfirmed = confirmed;

            return Task.CompletedTask;
        }

        public Task<CustomIdentityUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(normalizedEmail))
                throw new ArgumentNullException(nameof(normalizedEmail));

            var userEntity = _unitOfWork.UserRepository.FindByEmail(normalizedEmail);

            return Task.FromResult(getIdentityUser(userEntity));
        }

        public Task<string> GetNormalizedEmailAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.NormalizedEmail);
        }

        public Task SetNormalizedEmailAsync(CustomIdentityUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(normalizedEmail))
                throw new ArgumentNullException(nameof(normalizedEmail));

            user.NormalizedEmail = normalizedEmail;

            return Task.CompletedTask;
        }
        #endregion

        #region IUserLoginStore<CustomIdentityUser> Members
        public Task AddLoginAsync(CustomIdentityUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (login == null)
                throw new ArgumentNullException(nameof(login));

            var loginEntity = new UserLogin
            {
                LoginProvider = login.LoginProvider,
                ProviderDisplayName = login.ProviderDisplayName,
                ProviderKey = login.ProviderKey,
                UserId = user.Id
            };

            _unitOfWork.UserLoginRepository.Add(loginEntity);
            _unitOfWork.Commit();

            return Task.CompletedTask;
        }

        public Task RemoveLoginAsync(CustomIdentityUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentNullException(nameof(loginProvider));

            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentNullException(nameof(providerKey));

            var loginEntity = _unitOfWork.UserLoginRepository.Find(new { LoginProvider = loginProvider, ProviderKey = providerKey });
            if(loginEntity != null)
            {
                _unitOfWork.UserLoginRepository.Remove(loginEntity);
                _unitOfWork.Commit();
            }

            return Task.CompletedTask;
        }

        public Task<IList<UserLoginInfo>> GetLoginsAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            IList<UserLoginInfo> result = _unitOfWork.UserLoginRepository.GetByUserId(user.Id)
                .Select(x => new UserLoginInfo(x.LoginProvider, x.ProviderKey, x.ProviderDisplayName))
                .ToList();

            return Task.FromResult(result);
        }

        public Task<CustomIdentityUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentNullException(nameof(loginProvider));

            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentNullException(nameof(providerKey));

            var loginEntity = _unitOfWork.UserLoginRepository.GetByProviderAndKey(loginProvider, providerKey);
            if (loginEntity == null)
                return Task.FromResult(default(CustomIdentityUser));

            var userEntity = _unitOfWork.UserRepository.Find(loginEntity.UserId);

            return Task.FromResult(getIdentityUser(userEntity));
        }
        #endregion

        #region IUserRoleStore<CustomIdentityUser> Members
        public Task AddToRoleAsync(CustomIdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentNullException(nameof(roleName));

            var userEntity = getUserEntity(user);
            var roleEntity = _unitOfWork.RoleRepository.FindByName(roleName);

            if(roleEntity != null)
            {
                _unitOfWork.UserRoleRepository.Add(userEntity, roleEntity);
                _unitOfWork.Commit();
            }

            return Task.CompletedTask;
        }

        public Task RemoveFromRoleAsync(CustomIdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentNullException(nameof(roleName));

            var userEntity = getUserEntity(user);
            var roleEntity = _unitOfWork.RoleRepository.FindByName(roleName);

            if (roleEntity != null)
            {
                _unitOfWork.UserRoleRepository.Remove(userEntity, roleEntity);
                _unitOfWork.Commit();
            }

            return Task.CompletedTask;
        }

        public Task<IList<string>> GetRolesAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var userEntity = getUserEntity(user);

            IList<string> result = _unitOfWork.UserRoleRepository.GetRolesByUser(userEntity)
                .Select(x => x.Name)
                .ToList();

            return Task.FromResult(result);
        }

        public Task<bool> IsInRoleAsync(CustomIdentityUser user, string roleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentNullException(nameof(roleName));

            var userEntity = getUserEntity(user);

            var result = _unitOfWork.UserRoleRepository.GetRolesByUser(userEntity).Any(x => x.Name == roleName);
            return Task.FromResult(result);
        }

        public Task<IList<CustomIdentityUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(roleName))
                throw new ArgumentNullException(nameof(roleName));

            var roleEntity = _unitOfWork.RoleRepository.FindByName(roleName);
            if(roleEntity != null)
            {
                IList<CustomIdentityUser> result = _unitOfWork.UserRoleRepository.GetUsersByRole(roleEntity)
                    .Select(x => getIdentityUser(x))
                    .ToList();

                return Task.FromResult(result);
            }

            return Task.FromResult(default(IList<CustomIdentityUser>));
        }
        #endregion

        #region IUserSecurityStampStore<CustomIdentityUser> Members
        public Task SetSecurityStampAsync(CustomIdentityUser user, string stamp, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.SecurityStamp = stamp;

            return Task.CompletedTask;
        }

        public Task<string> GetSecurityStampAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.SecurityStamp);
        }
        #endregion

        #region IUserClaimStore<CustomIdentityUser> Members
        public Task<IList<Claim>> GetClaimsAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var userEntity = getUserEntity(user);

            IList<Claim> result = _unitOfWork.UserClaimRepository.GetByUser(userEntity)
                .Select(x => new Claim(x.ClaimType, x.ClaimValue)).ToList();

            return Task.FromResult(result);
        }

        public Task AddClaimsAsync(CustomIdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (claims == null)
                throw new ArgumentNullException(nameof(claims));

            var userEntity = getUserEntity(user);

            var claimEntities = claims.Select(x => getUserClaimEntity(x, userEntity));
            if(claimEntities.Count() > 0)
            {
                foreach (var claimEntity in claimEntities)
                {
                    _unitOfWork.UserClaimRepository.Add(claimEntity);
                }
                _unitOfWork.Commit();
            }

            return Task.CompletedTask;
        }

        public Task ReplaceClaimAsync(CustomIdentityUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            if (newClaim == null)
                throw new ArgumentNullException(nameof(newClaim));

            var userEntity = getUserEntity(user);
            var claimEntity = _unitOfWork.UserClaimRepository.GetByUser(userEntity)
                .FirstOrDefault(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);

            if(claimEntity != null)
            {
                claimEntity.ClaimType = newClaim.Type;
                claimEntity.ClaimValue = newClaim.Value;

                _unitOfWork.UserClaimRepository.Update(claimEntity);
            }

            return Task.CompletedTask;
        }

        public Task RemoveClaimsAsync(CustomIdentityUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (claims == null)
                throw new ArgumentNullException(nameof(claims));

            var userEntity = getUserEntity(user);

            if (claims.Count() > 0)
            {
                foreach (var claim in claims)
                {
                    var userClaimEntity = getUserClaimEntity(claim, userEntity);
                    _unitOfWork.UserClaimRepository.Remove(userClaimEntity);
                }
                _unitOfWork.Commit();
            }

            return Task.CompletedTask;
        }

        public Task<IList<CustomIdentityUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            IList<CustomIdentityUser> result = _unitOfWork.UserClaimRepository.GetUsersForClaim(claim.Type, claim.Value).Select(x => getIdentityUser(x)).ToList();

            return Task.FromResult(result);
        }
        #endregion

        #region IUserAuthenticationTokenStore<CustomIdentityUser> Members
        public Task SetTokenAsync(CustomIdentityUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentNullException(nameof(loginProvider));

            if(string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            if (string.IsNullOrWhiteSpace(value))
                throw new ArgumentNullException(nameof(value));

            var userTokenEntity = new UserToken
            {
                LoginProvider = loginProvider,
                Name = name,
                Value = value,
                UserId = user.Id
            };

            _unitOfWork.UserTokenRepository.Add(userTokenEntity);
            _unitOfWork.Commit();

            return Task.CompletedTask;
        }

        public Task RemoveTokenAsync(CustomIdentityUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentNullException(nameof(loginProvider));

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            var userTokenEntity = _unitOfWork.UserTokenRepository.Find(new { UserId = user.Id, LoginProvider = loginProvider, Name = name });
            if(userTokenEntity != null)
            {
                _unitOfWork.UserTokenRepository.Remove(userTokenEntity);
                _unitOfWork.Commit();
            }

            return Task.CompletedTask;
        }

        public Task<string> GetTokenAsync(CustomIdentityUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentNullException(nameof(loginProvider));

            if (string.IsNullOrWhiteSpace(name))
                throw new ArgumentNullException(nameof(name));

            var userTokenEntity = _unitOfWork.UserTokenRepository.Find(new { UserId = user.Id, LoginProvider = loginProvider, Name = name });

            return Task.FromResult(userTokenEntity?.Name);
        }
        #endregion

        #region Private Methods
        private User getUserEntity(CustomIdentityUser identityUser)
        {
            if (identityUser == null)
                return null;

            var result = new User();
            populateUserEntity(result, identityUser);

            return result;
        }

        private void populateUserEntity(User entity, CustomIdentityUser identityUser)
        {
            entity.AccessFailedCount = identityUser.AccessFailedCount;
            entity.ConcurrencyStamp = identityUser.ConcurrencyStamp;
            entity.Email = identityUser.Email;
            entity.EmailConfirmed = identityUser.EmailConfirmed;
            entity.Id = identityUser.Id;
            entity.LockoutEnabled = identityUser.LockoutEnabled;
            entity.LockoutEnd = identityUser.LockoutEnd;
            entity.NormalizedEmail = identityUser.NormalizedEmail;
            entity.NormalizedUserName = identityUser.NormalizedUserName;
            entity.PasswordHash = identityUser.PasswordHash;
            entity.PhoneNumber = identityUser.PhoneNumber;
            entity.PhoneNumberConfirmed = identityUser.PhoneNumberConfirmed;
            entity.SecurityStamp = identityUser.SecurityStamp;
            entity.TwoFactorEnabled = identityUser.TwoFactorEnabled;
            entity.UserName = identityUser.UserName;
        }

        private CustomIdentityUser getIdentityUser(User entity)
        {
            if (entity == null)
                return null;

            var result = new CustomIdentityUser();
            populateIdentityUser(result, entity);

            return result;
        }

        private void populateIdentityUser(CustomIdentityUser identityUser, User entity)
        {
            identityUser.AccessFailedCount = entity.AccessFailedCount;
            identityUser.ConcurrencyStamp = entity.ConcurrencyStamp;
            identityUser.Email = entity.Email;
            identityUser.EmailConfirmed = entity.EmailConfirmed;
            identityUser.Id = entity.Id;
            identityUser.LockoutEnabled = entity.LockoutEnabled;
            identityUser.LockoutEnd = entity.LockoutEnd;
            identityUser.NormalizedEmail = entity.NormalizedEmail;
            identityUser.NormalizedUserName = entity.NormalizedUserName;
            identityUser.PasswordHash = entity.PasswordHash;
            identityUser.PhoneNumber = entity.PhoneNumber;
            identityUser.PhoneNumberConfirmed = entity.PhoneNumberConfirmed;
            identityUser.SecurityStamp = entity.SecurityStamp;
            identityUser.TwoFactorEnabled = entity.TwoFactorEnabled;
            identityUser.UserName = entity.UserName;
        }

        private UserClaim getUserClaimEntity(Claim value, User userEntity)
        {
            return value == null
                ? default(UserClaim)
                : new UserClaim
                {
                    ClaimType = value.Type,
                    ClaimValue = value.Value,
                    UserId = userEntity.Id
                };
        }
        #endregion

        #region IUserTwoFactorStore<CustomIdentityUser> Members
        public Task SetTwoFactorEnabledAsync(CustomIdentityUser user, bool enabled, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.TwoFactorEnabled = enabled;

            return Task.CompletedTask;
        }

        public Task<bool> GetTwoFactorEnabledAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.TwoFactorEnabled);
        }
        #endregion

        #region IUserPhoneNumberStore<CustomIdentityUser> Members
        public Task SetPhoneNumberAsync(CustomIdentityUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.PhoneNumber = phoneNumber;

            return Task.CompletedTask;
        }

        public Task<string> GetPhoneNumberAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(CustomIdentityUser user, bool confirmed, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.PhoneNumberConfirmed = confirmed;

            return Task.CompletedTask;
        }
        #endregion

        #region IUserLockoutStore<CustomIdentityUser> Members
        public Task<DateTimeOffset?> GetLockoutEndDateAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.LockoutEnd);
        }

        public Task SetLockoutEndDateAsync(CustomIdentityUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.LockoutEnd = lockoutEnd;

            return Task.CompletedTask;
        }

        public Task<int> IncrementAccessFailedCountAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(++user.AccessFailedCount);
        }

        public Task ResetAccessFailedCountAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.AccessFailedCount = 0;

            return Task.CompletedTask;
        }

        public Task<int> GetAccessFailedCountAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<bool> GetLockoutEnabledAsync(CustomIdentityUser user, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.LockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(CustomIdentityUser user, bool enabled, CancellationToken cancellationToken)
        {
            if (cancellationToken != null)
                cancellationToken.ThrowIfCancellationRequested();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            user.LockoutEnabled = enabled;

            return Task.CompletedTask;
        }
        #endregion
    }
}
