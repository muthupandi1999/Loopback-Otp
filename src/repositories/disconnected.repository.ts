import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MysqlDataSource} from '../datasources';
import {Disconnected, DisconnectedRelations} from '../models';

export class DisconnectedRepository extends DefaultCrudRepository<
  Disconnected,
  typeof Disconnected.prototype.id,
  DisconnectedRelations
> {
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
  ) {
    super(Disconnected, dataSource);
  }
}
