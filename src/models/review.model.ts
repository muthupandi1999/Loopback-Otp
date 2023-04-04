import {Entity, model, property} from '@loopback/repository';

@model()
export class Review extends Entity {
    @property({
        type: 'number',
        id: true,
        generated: true,
    })
    id?: number;

    @property({
        type: 'number',
        required: true,
    })
    userId: number;

    @property({
        type: 'boolean',
        required: true,
    })
    isAnonymous: boolean;

    @property({
        type: 'number',
        required: true,
    })
    rating: number;

    @property({
        type: 'number',
        required: true,
    })
    employeeId: number;

    @property({
        type: 'boolean',
        required: true,
    })
    isActive: boolean;

    @property({
        type: 'string',
        required: true,
    })
    review: string;

    @property({
        type: 'date',
        default: new Date()
    })
    updated_date?: Date;

    @property({
        type: 'date',
        default: "$now"
    })
    created_date?: string;

    @property({
        type: 'boolean',
        required: true,
    })
    isRemoved: boolean;


    constructor(data?: Partial<Review>) {
        super(data);
    }
}

export interface ReviewRelations {
    // describe navigational properties here
}

export type ReviewWithRelations = Review & ReviewRelations;
