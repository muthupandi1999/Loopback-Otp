import {Entity, model, property, belongsTo} from '@loopback/repository';
import {User} from '.';


@model()
export class Otp extends Entity {
  
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
  otp: string;

  @property({
    type: 'string',
    required: true,
  })
  type: string;

  @property({
    type: 'object',
    required: true,
  })
  data: object;

  @belongsTo(() => User)
  userId: number;

  constructor(data?: Partial<Otp>) {
    super(data);
  }
}

export interface OtpRelations {
  user?: User;
}

export type OtpWithRelations = Otp & OtpRelations;