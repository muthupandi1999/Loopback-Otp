import { Entity, model, property } from '@loopback/repository';

@model()
export class SmsRequest  extends Entity {
    @property({
        type: 'string',
        required: true,
    })
    to: string;

    @property({
        type: 'string',
        required: true,
    })
    message: string;
    text: any;

    constructor(data?: Partial<SmsRequest >) {
        super(data);
    }
}
