import {Count, CountSchema, Filter, FilterExcludingWhere, repository,} from '@loopback/repository';
import {get, getModelSchemaRef, param, post, requestBody, response,} from '@loopback/rest';
import {Feedback} from '../models';
import {FeedbackRepository} from '../repositories';
import {authenticate, AuthenticationBindings} from "@loopback/authentication";
import {inject} from "@loopback/core";
import {UserProfile} from "@loopback/security";

export class FeedbackController {
    constructor(
        @repository(FeedbackRepository)
        public feedbackRepository: FeedbackRepository,
    ) {
    }

    @authenticate('jwt')
    @post('/feedbacks')
    @response(200, {
        description: 'Feedback model instance',
        content: {'application/json': {schema: getModelSchemaRef(Feedback)}},
    })
    async create(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(Feedback, {
                        title: 'NewFeedback',
                        exclude: ['id', 'createdOn', 'userId'],
                    }),
                },
            },
        })
        @inject(AuthenticationBindings.CURRENT_USER)
            currentUser: UserProfile,
        feedback: Omit<Feedback, 'id'>,
    ): Promise<Feedback> {
        feedback.userId = currentUser.id
        return this.feedbackRepository.create(feedback);
    }

    @authenticate('jwt')
    @get('/feedbacks/count')
    @response(200, {
        description: 'Feedback model count',
        content: {'application/json': {schema: CountSchema}},
    })
    async count(): Promise<Count> {
        return this.feedbackRepository.count();
    }

    @authenticate('jwt')
    @get('/feedbacks')
    @response(200, {
        description: 'Array of Feedback model instances',
        content: {
            'application/json': {
                schema: {
                    type: 'array',
                    items: getModelSchemaRef(Feedback, {includeRelations: true}),
                },
            },
        },
    })
    async find(): Promise<Feedback[]> {
        return this.feedbackRepository.find();
    }

    @authenticate('jwt')
    @get('/feedbacks/{id}')
    @response(200, {
        description: 'Feedback model instance',
        content: {
            'application/json': {
                schema: getModelSchemaRef(Feedback, {includeRelations: true}),
            },
        },
    })
    async findById(
        @param.path.number('id') id: number,
        @param.filter(Feedback, {exclude: 'where'}) filter?: FilterExcludingWhere<Feedback>
    ): Promise<Feedback> {
        return this.feedbackRepository.findById(id, filter);
    }
}
