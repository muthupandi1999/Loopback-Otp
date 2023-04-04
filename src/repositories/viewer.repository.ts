import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MysqlDataSource} from '../datasources';
import {Viewer, ViewerRelations} from '../models';

export class ViewerRepository extends DefaultCrudRepository<
  Viewer,
  typeof Viewer.prototype.id,
  ViewerRelations
> {
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
  ) {
    super(Viewer, dataSource);
  }
}
