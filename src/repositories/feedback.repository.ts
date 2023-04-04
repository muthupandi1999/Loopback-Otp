import {Getter, inject} from '@loopback/core';
import {BelongsToAccessor, DefaultCrudRepository, repository} from '@loopback/repository';
import {MysqlDataSource} from '../datasources';
import {Feedback, FeedbackMaster, FeedbackRelations} from '../models';
import {FeedbackMasterRepository} from "./feedback-master.repository";

export class FeedbackRepository extends DefaultCrudRepository<
  Feedback,
  typeof Feedback.prototype.id,
  FeedbackRelations
> {
  public readonly feedbackMaster: BelongsToAccessor<
      FeedbackMaster,
      typeof Feedback.prototype.id
  >;
  constructor(
    @inject('datasources.mysql') dataSource: MysqlDataSource,
    @repository.getter('FeedbackMasterRepository')
        feedbackMasterRepositoryGetter: Getter<FeedbackMasterRepository>,
  ) {
    super(Feedback, dataSource);
    this.feedbackMaster = this.createBelongsToAccessorFor(
        'id',
        feedbackMasterRepositoryGetter,
    );
  }
}
