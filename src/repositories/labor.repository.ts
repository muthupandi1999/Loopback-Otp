import { Getter, inject } from '@loopback/core';
import { BelongsToAccessor, DefaultCrudRepository, repository } from '@loopback/repository';

import { MysqlDataSource } from '../datasources';
import { Labor, LaborRelations, User } from '../models';
import { UserRepository } from './user.repository';

export class LaborRepository extends DefaultCrudRepository<
  Labor,
  typeof Labor.prototype.id,
  LaborRelations
> {
  public readonly user: BelongsToAccessor<
  User,
  typeof User.prototype.id
  >
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
    @repository.getter('UserRepository')
    userRepositoryGetter: Getter<UserRepository>,
  ) {
    super(Labor, dataSource);
    this.user = this.createBelongsToAccessorFor(
      'user',
        userRepositoryGetter
      );
  }

}
