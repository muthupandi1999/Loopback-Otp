import {Entity, model, property} from '@loopback/repository';

@model()
export class FeedbackMaster extends Entity {
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
    type: string;

    @property({
        type: 'string',
        required: true,
    })
    description: string;


    constructor(data?: Partial<FeedbackMaster>) {
        super(data);
    }
}

export interface FeedbackMasterRelations {
    // describe navigational properties here
}

export type FeedbackMasterWithRelations = FeedbackMaster & FeedbackMasterRelations;
