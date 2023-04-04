import {inject} from '@loopback/core';
import {DefaultCrudRepository} from '@loopback/repository';
import {MysqlDataSource} from '../datasources';
import {Otp, OtpRelations} from '../models';

export class OtpRepository extends DefaultCrudRepository<
  Otp,
  typeof Otp.prototype.id,
  OtpRelations
> {
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
  ) {
    super(Otp, dataSource);
  }
}
