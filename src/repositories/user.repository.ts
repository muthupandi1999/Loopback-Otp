import {inject} from '@loopback/core';
import {DefaultCrudRepository, Filter, HasManyRepositoryFactory, Options, repository} from '@loopback/repository';
import {MysqlDataSource} from '../datasources';
import {User, UserRelations} from '../models';

export type Credentials = {
  email: string;
  
};


export class UserRepository extends DefaultCrudRepository<
  User,
  typeof User.prototype.id,
  UserRelations
> {
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
  ) {
    super(User, dataSource);
  }

  async findPaginated(filter?: Filter<User>, options?: Options): Promise<any> {
    const page = await this.find(filter, options);
    const count = await this.count(filter.where);
    return {
      data: page,
      count,
      ...options,
    };
  }
}
