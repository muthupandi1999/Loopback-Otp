import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MysqlDataSource} from '../datasources';
import {FeedbackMaster, FeedbackMasterRelations} from '../models';

export class FeedbackMasterRepository extends DefaultCrudRepository<
  FeedbackMaster,
  typeof FeedbackMaster.prototype.id,
  FeedbackMasterRelations
> {
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
  ) {
    super(FeedbackMaster, dataSource);
  }
}
