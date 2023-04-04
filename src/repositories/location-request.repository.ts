import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MysqlDataSource} from '../datasources';
import {LocationRequest, LocationRequestRelations} from '../models';

export class LocationRequestRepository extends DefaultCrudRepository<
  LocationRequest,
  typeof LocationRequest.prototype.id,
  LocationRequestRelations
> {
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
  ) {
    super(LocationRequest, dataSource);
  }
}
