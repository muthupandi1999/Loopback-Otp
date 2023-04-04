import {repository,} from '@loopback/repository';
import {get, getModelSchemaRef, response,} from '@loopback/rest';
import {FeedbackMaster} from '../models';
import {FeedbackMasterRepository} from '../repositories';

export class FeedbackMasterController {
  constructor(
    @repository(FeedbackMasterRepository)
    public feedbackMasterRepository : FeedbackMasterRepository,
  ) {}

  @get('/feedback-master')
  @response(200, {
    description: 'Array of FeedbackMaster model instances',
    content: {
      'application/json': {
        schema: {
          type: 'array',
          items: getModelSchemaRef(FeedbackMaster, {includeRelations: true}),
        },
      },
    },
  })
  async find(): Promise<FeedbackMaster[]> {
    return this.feedbackMasterRepository.find();
  }
}
