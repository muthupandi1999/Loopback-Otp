import {Entity, model, property} from '@loopback/repository';

@model({settings: {strict: true}})
export class User extends Entity {
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
  name: string;

  @property({
    type: 'array',
    itemType: 'string',
    required: true,
  })
  role: string[];

  @property({
    type: 'string',
    required: true,
  })
  email: string;

  @property({
    type: 'string',
    required: true,
  })
  username: string;

  @property({
    type: 'boolean',
    default: false,
  })
  isDelete: boolean;

  @property({
    type: 'boolean',
    default: false,
  })
  tfa: boolean;

  @property({
    type: 'boolean',
    default: true,
  })
  active: boolean;

  @property({
    type: 'string',
    default: null,
  })
  messageToken: string;

  @property({
    type: 'number',
    default: 0,
  })
  limit?: number;

  // Define well-known properties here

  // Indexer property to allow additional data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [prop: string]: any;

  constructor(data?: Partial<User>) {
    super(data);
  }
}

export interface UserRelations {
  // describe navigational properties here
}

export type UserWithRelations = User & UserRelations;
