using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCoreIdentityExample.Domain.Repositories
{
    public interface IRepository<TEntity> where TEntity : class
    {
        IEnumerable<TEntity> GetAll();
        Task<IEnumerable<TEntity>> GetAllAsync();
        Task<IEnumerable<TEntity>> GetAllAsync(CancellationToken cancellationToken);

        TEntity Find(object id);
        Task<TEntity> FindAsync(object id);
        Task<TEntity> FindAsync(CancellationToken cancellationToken, object id);

        void Add(TEntity entity);
        Task AddAsync(TEntity entity);
        Task AddAsync(CancellationToken cancellationToken, TEntity entity);

        void Update(TEntity entity);
        Task UpdateAsync(TEntity entity);
        Task UpdateAsync(CancellationToken cancellationToken, TEntity entity);

        void Remove(TEntity entity);
        Task RemoveAsync(TEntity entity);
        Task RemoveAsync(CancellationToken cancellationToken, TEntity entity);
    }
}
