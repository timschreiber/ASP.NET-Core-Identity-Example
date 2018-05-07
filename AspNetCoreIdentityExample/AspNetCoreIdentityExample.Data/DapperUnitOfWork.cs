using AspNetCoreIdentityExample.Data.Repositories;
using AspNetCoreIdentityExample.Domain;
using AspNetCoreIdentityExample.Domain.Entities;
using AspNetCoreIdentityExample.Domain.Repositories;
using System;
using System.Data;
using System.Data.SqlClient;

namespace AspNetCoreIdentityExample.Data
{
    public class DapperUnitOfWork : IUnitOfWork
    {
        #region Fields
        private IDbConnection _connection;
        private IDbTransaction _transaction;
        private IRoleRepository _roleRepository;
        private IRoleClaimRepository _roleClaimRepository;
        private IUserRepository _userRepository;
        private IUserClaimRepository _userClaimRepository;
        private IUserLoginRepository _userLoginRepository;
        private IRepository<UserToken, UserTokenKey> _userTokenRepository;
        private IUserRoleRepository _userRoleRepository;
        private bool _disposed;
        #endregion

        public DapperUnitOfWork(string connectionString)
        {
            _connection = new SqlConnection(connectionString);
            _connection.Open();
            _transaction = _connection.BeginTransaction();
        }

        #region IUnitOfWork Members
        public IRoleRepository RoleRepository
        {
            get
            {
                return _roleRepository
                    ?? (_roleRepository = new RoleRepository(_transaction));
            }
        }

        public IRoleClaimRepository RoleClaimRepository
        {
            get
            {
                return _roleClaimRepository
                    ?? (_roleClaimRepository = new RoleClaimRepository(_transaction));
            }
        }

        public IUserRepository UserRepository
        {
            get
            {
                return _userRepository
                    ?? (_userRepository = new UserRepository(_transaction));
            }
        }

        public IUserClaimRepository UserClaimRepository
        {
            get
            {
                return _userClaimRepository
                    ?? (_userClaimRepository = new UserClaimRepository(_transaction));
            }
        }
        
        public IUserLoginRepository UserLoginRepository
        {
            get
            {
                return _userLoginRepository
                    ?? (_userLoginRepository = new UserLoginRepository(_transaction));
            }
        }

        public IRepository<UserToken, UserTokenKey> UserTokenRepository
        {
            get
            {
                return _userTokenRepository
                    ?? (_userTokenRepository = new UserTokenRepository(_transaction));
            }
        }

        public IUserRoleRepository UserRoleRepository
        {
            get
            {
                return _userRoleRepository
                    ?? (_userRoleRepository = new UserRoleRepository(_transaction));
            }
        }

        public void Commit()
        {
            try
            {
                _transaction.Commit();
            }
            catch
            {
                _transaction.Rollback();
            }
            finally
            {
                _transaction.Dispose();
                resetRepositories();
                _transaction = _connection.BeginTransaction();
            }
        }

        public void Dispose()
        {
            dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion

        #region Private Methods
        private void resetRepositories()
        {
            _roleRepository = null;
            _roleClaimRepository = null;
            _userRepository = null;
            _userClaimRepository = null;
            _userLoginRepository = null;
            _userTokenRepository = null;
            _userRoleRepository = null;
        }

        private void dispose(bool disposing)
        {
            if(!_disposed)
            {
                if(disposing)
                {
                    if(_transaction != null)
                    {
                        _transaction.Dispose();
                        _transaction = null;
                    }
                    if(_connection != null)
                    {
                        _connection.Dispose();
                        _connection = null;
                    }
                }
                _disposed = true;
            }
        }

        ~DapperUnitOfWork()
        {
            dispose(false);
        }
        #endregion
    }
}
