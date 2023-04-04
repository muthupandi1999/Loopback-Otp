import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MysqlDataSource} from '../datasources';
import {Employer, EmployerRelations} from '../models';

export class EmployerRepository extends DefaultCrudRepository<
  Employer,
  typeof Employer.prototype.id,
  EmployerRelations
> {
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
  ) {
    super(Employer, dataSource);
  }
}
