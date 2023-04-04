import {Getter, inject} from '@loopback/core';
import {DefaultCrudRepository, BelongsToAccessor, repository} from '@loopback/repository';
import {MysqlDataSource} from '../datasources';
import {Awards, AwardsSubStatus, AwardsSubStatusRelations} from '../models';
import { AwardsRepository } from './awards.repository';

export class AwardsSubStatusRepository extends DefaultCrudRepository<
  AwardsSubStatus,
  typeof AwardsSubStatus.prototype.id,
  AwardsSubStatusRelations
> {
  public readonly awards: BelongsToAccessor<
  Awards,
  typeof Awards.prototype.id
>;
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
    @repository.getter('AwardsRepository')
    protected awardRepositoryGetter: Getter<AwardsRepository>,
  ) {
    super(AwardsSubStatus, dataSource);

    this.awards = this.createBelongsToAccessorFor(
      'awards',
      awardRepositoryGetter
    )
    this.registerInclusionResolver('awards', this.awards.inclusionResolver)
  }
}
