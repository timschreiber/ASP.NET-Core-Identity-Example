using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace AspNetCoreIdentityExample.Domain.Repositories
{
    public interface IRepository<TEntity, TKey> where TEntity : class
    {
        IEnumerable<TEntity> All();

        TEntity Find(TKey key);

        void Add(TEntity entity);

        void Update(TEntity entity);

        void Remove(TKey key);
    }
}
