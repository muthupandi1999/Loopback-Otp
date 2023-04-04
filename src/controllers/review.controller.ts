import {Count, CountSchema, Filter, repository,} from '@loopback/repository';
import {del, get, getModelSchemaRef, HttpErrors, param, patch, post, requestBody, response,} from '@loopback/rest';
import {Review} from '../models';
import {AwardsRepository, LaborRepository, ReviewRepository} from '../repositories';
import {authenticate, AuthenticationBindings} from "@loopback/authentication";
import {inject} from "@loopback/core";
import {UserProfile} from "@loopback/security";
import {authorize} from "@loopback/authorization";
import {authorizeUser} from "../services/authorizeUser";

export class ReviewController {
    constructor(
        @repository(ReviewRepository)
        public reviewRepository: ReviewRepository,
        @repository(LaborRepository)
        public awardRepository: AwardsRepository,
    ) {
    }

    @authenticate('jwt')
    @post('/reviews')
    @response(200, {
        description: 'Review model instance',
        content: {'application/json': {schema: getModelSchemaRef(Review)}},
    })
    async create(
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(Review, {
                        title: 'NewReview',
                        exclude: ['id', 'userId', 'updated_date', 'created_date', 'isRemoved', 'isActive'],
                    }),
                },
            },
        })
        @inject(AuthenticationBindings.CURRENT_USER) currentUser: UserProfile,
        review: Omit<Review, 'id'>,
    ): Promise<any> {
        review.userId = currentUser.id
        review.isRemoved = false
        review.isActive = false //Keep the post inactive until approved by the Admin.
        this.validateRating(review.rating)
        this.validateReview(review.review)

        await this.ensureJobWasAwarded(currentUser.id, review.employeeId)

        await this.reviewRepository.create(review);
        return
    }

    @authenticate('jwt')
    @get('/reviews/count')
    @response(200, {
        description: 'Review model count',
        content: {'application/json': {schema: CountSchema}},
    })
    async count(@inject(AuthenticationBindings.CURRENT_USER) currentUser: UserProfile): Promise<Count> {
        return this.reviewRepository.count({userId: currentUser.id});
    }

    @authenticate('jwt')
    @get('/reviews')
    @response(200, {
        description: 'Array of Review model instances',
        content: {
            'application/json': {
                schema: {
                    type: 'array',
                    items: getModelSchemaRef(Review, {includeRelations: true}),
                },
            },
        },
    })
    async find(
        @inject(AuthenticationBindings.CURRENT_USER) currentUser: UserProfile,
        @param.filter(Review) filter?: Filter
    ) {
        //For usage of filter https://stackoverflow.com/a/55135831
        return this.reviewRepository.find({
            fields: {
                id: true,
                isAnonymous: true,
                rating: true,
                employeeId: true,
                review: true,
                created_date: true,
                updated_date: true,
            },
            where: {userId: currentUser.id, isRemoved: false},
            offset: filter?.offset,
            limit: filter?.limit,
            skip: filter?.skip
        },);
    }

    @authenticate('jwt')
    @get('/reviews/{id}')
    @response(200, {
        description: 'Review model instance',
        content: {
            'application/json': {
                schema: getModelSchemaRef(Review, {
                    partial: true, exclude: [
                        'id',
                        "userId",
                        "isAnonymous",
                        "employeeId",
                        "updated_date",
                        "created_date",
                        "isActive",
                        "isRemoved"]
                }),
            },
        },
    })
    async findById(
        @inject(AuthenticationBindings.CURRENT_USER) currentUser: UserProfile,
        @param.path.number('id') id: number,
    ) {
        return this.reviewRepository.find({
            fields: {
                id: true,
                isAnonymous: true,
                rating: true,
                employeeId: true,
                review: true,
                created_date: true,
                updated_date: true,
            },
            where: {userId: currentUser.id, id: id, isRemoved: false},
        });
    }

    @authenticate('jwt')
    @patch('/reviews/{id}')
    @response(204, {
        description: 'Review PATCH success',
    })
    async updateById(
        @inject(AuthenticationBindings.CURRENT_USER) currentUser: UserProfile,
        @param.path.number('id') id: number,
        @requestBody({
            content: {
                'application/json': {
                    schema: getModelSchemaRef(Review, {
                        partial: true, exclude: [
                            'id', "userId", "isAnonymous",
                            "employeeId", "updated_date",
                            "created_date", "isActive", "isRemoved"]
                    }),
                },
            },
        })
            review: Review,
    ): Promise<any> {
        this.validateRating(review.rating)
        this.validateReview(review.review)
        await this.ensureJobWasAwarded(currentUser.id, review.employeeId)

        review.updated_date = new Date();
        return await this.reviewRepository.updateAll(review, {id: id, userId: currentUser.id})
    }

    @authenticate('jwt')
    @del('/reviews/{id}')
    @response(204, {
        description: 'Review DELETE success',
    })
    async deleteById(
        @inject(AuthenticationBindings.CURRENT_USER) currentUser: UserProfile,
        @param.path.number('id') id: number
    ): Promise<void> {
        let review = await this.reviewRepository.findById(id)
        review.isRemoved = true
        let count = await this.reviewRepository.updateAll(review, {id: id, userId: currentUser.id})
        if (count.count !== 0) {
            return //At least one entry is marked as deleted
        } else {
            throw HttpErrors.NotFound("Cannot find Id " + id)
        }
    }

    @authenticate("jwt")
    @authorize({
        allowedRoles: ["admin"],
        voters: [authorizeUser],
    })
    @get('admin/reviews/count')
    @response(200, {
        description: 'Gets the entire review count for all users',
        content: {'application/json': {schema: CountSchema}},
    })
    async adminCount(): Promise<Count> {
        return this.reviewRepository.count();
    }

    @authenticate('jwt')
    @authorize({
        allowedRoles: ["admin"],
        voters: [authorizeUser],
    })
    @get('admin/reviews')
    @response(200, {
        description: 'Array of Review model instances',
        content: {
            'application/json': {
                schema: {
                    type: 'array',
                    items: getModelSchemaRef(Review, {includeRelations: true}),
                },
            },
        },
    })
    async adminFind(
        @param.filter(Review) filter?: Filter
    ) {
        //For usage of filter https://stackoverflow.com/a/55135831
        return this.reviewRepository.find({
            offset: filter?.offset,
            limit: filter?.limit,
            skip: filter?.skip
        },);
    }


    @authenticate('jwt')
    @authorize({
        allowedRoles: ["admin"],
        voters: [authorizeUser],
    })
    @del('admin/reviews/{id}')
    @response(204, {
        description: 'Review DELETE success',
    })
    async adminDeleteById(
        @param.path.number('id') id: number
    ): Promise<void> {
        let review = await this.reviewRepository.findById(id)
        review.isRemoved = true
        let count = await this.reviewRepository.updateAll(review, {id: id})
        if (count.count !== 0) {
            return //At least one entry is marked as deleted
        } else {
            throw HttpErrors.NotFound("Cannot find Id " + id)
        }
    }

    @authenticate('jwt')
    @authorize({
        allowedRoles: ["admin"],
        voters: [authorizeUser],
    })
    @patch('admin/reviews/{id}/approve')
    @response(204, {
        description: 'Review approved',
    })
    async adminApproveById(
        @param.path.number('id') id: number
    ): Promise<void> {
        let review = await this.reviewRepository.findById(id)
        review.isActive = true
        let count = await this.reviewRepository.updateAll(review, {id: id})
        if (count.count !== 0) {
            return //At least one entry is marked as deleted
        } else {
            throw HttpErrors.NotFound("Cannot find Id " + id)
        }
    }

    @authenticate('jwt')
    @authorize({
        allowedRoles: ["admin"],
        voters: [authorizeUser],
    })
    @patch('admin/reviews/{id}/reject')
    @response(204, {
        description: 'Review rejected',
    })
    async adminRejectById(
        @param.path.number('id') id: number
    ): Promise<void> {
        let review = await this.reviewRepository.findById(id)
        review.isActive = false
        let count = await this.reviewRepository.updateAll(review, {id: id})
        if (count.count !== 0) {
            return //At least one entry is marked as deleted
        } else {
            throw HttpErrors.NotFound("Cannot find Id " + id)
        }
    }


    private validateRating(rating: number) {
        if (rating > 5 || rating < 1) {
            throw HttpErrors.BadRequest("Rating should be a number from 1 to 5")
        }
    }

    private validateReview(review: string) {
        if (review.length > 500) {
            throw HttpErrors.BadRequest("Review exceeded the maximum character of 500")
        }
    }

    private async ensureJobWasAwarded(userId: number, labourId: number) {
        //TODO:For now skipping this validation. Once awards is working test this and remove the return statement
        return

        let awards = await this.awardRepository.find({where: {userId: userId, laborId: labourId}})

        let index = awards.findIndex((award) => {
            return award.awardsSubStatus.length > 0 //TODO:Add also the status
        })

        if (index < 0) {
            await Promise.reject(HttpErrors.Forbidden("Not allowed to rate this employee"))
        }
    }
}
