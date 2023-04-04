import {Getter, inject} from '@loopback/core';
import {DefaultCrudRepository, Filter, HasManyRepositoryFactory, Options, repository} from '@loopback/repository';
import {MysqlDataSource} from '../datasources';
import {Awards, AwardsSubStatus, AwardsWithRelations} from '../models';
import { AwardsSubStatusRepository } from './awards-sub-status.repository';

export class AwardsRepository extends DefaultCrudRepository<
  Awards,
  typeof Awards.prototype.id,
  AwardsWithRelations
> {
  public readonly awardSub: HasManyRepositoryFactory<
  AwardsSubStatus,
  typeof Awards.prototype.id
>;
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
    @repository.getter('AwardsSubStatusRepository')
    protected awardSubRepositoryGetter: Getter<AwardsSubStatusRepository>,
  ) {
    super(Awards, dataSource);
    this.awardSub = this.createHasManyRepositoryFactoryFor(
      'awardsSubStatus',
      awardSubRepositoryGetter,
    );

    this.registerInclusionResolver('awardsSubStatus', this.awardSub.inclusionResolver);
  }

  async findPaginated(filter?: Filter<Awards>, options?: Options): Promise<any> {
    const page = await this.find(filter, options);
    const count = await this.count(filter);

    return {
      data: page,
      count,
      ...options,
    };
  }
}
