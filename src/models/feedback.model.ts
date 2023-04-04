import {belongsTo, Entity, model, property} from '@loopback/repository';
import {FeedbackMaster} from "./feedback-master.model";

@model()
export class Feedback extends Entity {
    @property({
        type: 'number',
        id: true,
        generated: true,
    })
    id?: number;

    @property({
        type: 'string',
        required: true,
    })
    userId: string;

    @belongsTo(() => FeedbackMaster, {name: "id"})
    feedbackId: number;

    @property({
        type: 'string',
        required: true,
    })
    message: string;

    @property({
        type: 'date',
        default: '$now',
        required: true,
    })
    createdOn: string;

    constructor(data?: Partial<Feedback>) {
        super(data);
    }
}

export interface FeedbackRelations {
    // describe navigational properties here
}

export type FeedbackWithRelations = Feedback & FeedbackRelations;
